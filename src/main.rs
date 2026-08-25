use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use netinspect::cli::{self, Cli, Command};
use netinspect::model::{
    DnsConfig, Interface, PublicAddress, Reachability, RoutesReport, Snapshot, SCHEMA,
};
use netinspect::probe::{self, net::Net, Ladder};
use netinspect::public::{self, cache};
use netinspect::render::{human, json, routes as render_routes};
use netinspect::sys;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("netinspect: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    // Local collection is synchronous and takes microseconds. Have the whole
    // local report in hand before any network I/O starts.
    let platform = sys::platform(sys::PlatformConfig {
        helpers: cli.helper_policy(),
    });
    let interfaces = platform.interfaces()?;
    let dns = platform.dns_config()?;

    if let Some(Command::Routes { iface }) = &cli.command {
        return routes(&cli, platform.as_ref(), &interfaces, iface.as_deref());
    }

    let measured = if cli.probes_enabled() {
        Some(measure(&cli, &interfaces, &dns)?)
    } else {
        None
    };

    if matches!(cli.command, Some(Command::Check)) {
        return Ok(check(&cli, measured.as_ref().map(|m| &m.0)));
    }

    let (reachability, public) = match measured {
        Some((reachability, public)) => (Some(reachability), public),
        None => (None, None),
    };

    let snapshot = Snapshot {
        schema: SCHEMA,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        timestamp: now(),
        interfaces,
        dns,
        reachability,
        public,
        update: None,
    };

    let text = if cli.json {
        json::emit(&snapshot, cli.pretty)?
    } else {
        human::render(&snapshot, &cli.render_options(clock()))
            .trim_end()
            .to_owned()
    };
    println!("{text}");

    // The default command succeeded at its job of reporting, whatever the
    // network turned out to be doing. Only `check` encodes connectivity.
    Ok(ExitCode::SUCCESS)
}

fn routes(
    cli: &Cli,
    platform: &dyn sys::Platform,
    interfaces: &[Interface],
    iface: Option<&str>,
) -> Result<ExitCode> {
    let all = platform.routes(cli.family())?;

    let shown: Vec<_> = all
        .iter()
        .filter(|route| cli.all || render_routes::is_interesting(route))
        .filter(|route| match iface {
            Some(name) => route.interface.as_deref() == Some(name),
            None => true,
        })
        .cloned()
        .collect();
    let summary = render_routes::summarise(&shown, &all, interfaces);

    let text = if cli.json {
        json::emit(
            &RoutesReport {
                schema: SCHEMA,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                timestamp: now(),
                routes: shown,
                route_summary: summary,
            },
            cli.pretty,
        )?
    } else {
        render_routes::render(
            &shown,
            &summary,
            &render_routes::Options {
                theme: cli.theme(),
                edge: cli.content_edge(),
            },
        )
        .trim_end()
        .to_owned()
    };
    println!("{text}");
    Ok(ExitCode::SUCCESS)
}

/// Run the ladder, and the public lookup alongside it.
///
/// The lookup starts first and is *cancelled* if the ladder does not end
/// online: on a broken network its answer would be stale or absent anyway, and
/// there is no reason to keep telling a third party about a machine whose
/// report will not use the reply.
fn measure(
    cli: &Cli,
    interfaces: &[Interface],
    dns: &DnsConfig,
) -> Result<(Reachability, Option<PublicAddress>)> {
    let net = Arc::new(Net::new()?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let directory = cache::directory();
    let fingerprint = public::fingerprint(interfaces);
    let vpn_active = public::vpn_active(interfaces);
    let stored = directory.as_deref().and_then(cache::load);
    let now_unix = jiff::Timestamp::now().as_second();

    // A fresh cached answer means this run tells the provider nothing at all.
    let cached = stored
        .as_ref()
        .filter(|cache| cli.lookup_enabled() && cache::is_fresh(cache, &fingerprint, now_unix));
    if cli.verbose {
        eprintln!(
            "netinspect: geo cache {}",
            match (&cached, cli.lookup_enabled()) {
                (Some(cache), _) => format!("hit, {}s old", now_unix - cache.fetched_at_unix),
                (None, true) => "miss".to_owned(),
                (None, false) => "not consulted, lookup disabled".to_owned(),
            }
        );
    }

    let pending = match (cli.lookup_enabled(), cached.is_some()) {
        (true, false) => {
            let net = Arc::clone(&net);
            let endpoint = public::endpoint();
            let timeout = cli.probe_timeout();
            Some(runtime.spawn(async move {
                public::lookup(net.as_ref(), &endpoint, timeout).await
            }))
        }
        _ => None,
    };

    let ladder = Ladder {
        connector: net.as_ref(),
        resolver: net.as_ref(),
        http: net.as_ref(),
        timeout: cli.probe_timeout(),
    };
    let started = std::time::Instant::now();
    let reachability = runtime.block_on(ladder.run(interfaces, dns));
    if cli.verbose {
        eprintln!(
            "netinspect: reachability ladder finished in {} ms",
            started.elapsed().as_millis()
        );
    }

    let online = reachability.state == netinspect::model::ReachabilityState::Online;
    let observation = match (cached, pending) {
        (Some(cache), _) => Some((cache.observation.clone(), cache.fetched_at_unix)),
        (None, Some(task)) if online => runtime
            .block_on(task)
            .ok()
            .flatten()
            .map(|observed| (observed, now_unix)),
        (None, Some(task)) => {
            task.abort();
            None
        }
        (None, None) => None,
    };

    let Some((observation, fetched_at_unix)) = observation else {
        return Ok((reachability, None));
    };

    let baseline = cache::baseline_after(
        stored.as_ref().and_then(|cache| cache.baseline.clone()),
        &observation,
        vpn_active,
        fetched_at_unix,
    );
    let public = public::assemble(
        &observation,
        baseline.as_ref(),
        cli::system_timezone().as_deref(),
        vpn_active,
        Some(local_time(fetched_at_unix)),
    );

    if let Some(directory) = &directory {
        let record = cache::Cache {
            schema: 1,
            fingerprint,
            fetched_at_unix,
            observation,
            baseline,
        };
        if let Err(error) = cache::store(directory, &record) {
            if cli.verbose {
                eprintln!("netinspect: could not write the geo cache: {error}");
            }
        }
    }

    Ok((reachability, Some(public)))
}

/// `check` exists for scripting and shell prompts: silence is the success
/// message, and the verdict is the exit code.
fn check(cli: &Cli, reachability: Option<&Reachability>) -> ExitCode {
    let Some(report) = reachability else {
        eprintln!("netinspect: no reachability measurement was taken");
        return ExitCode::from(1);
    };
    if cli.verbose {
        println!("{}", report_line(report));
    }
    ExitCode::from(probe::exit_code(report.state) as u8)
}

fn report_line(report: &Reachability) -> String {
    let stage = |name: &str, ok: Option<bool>, ms: Option<u64>| match (ok, ms) {
        (Some(true), Some(ms)) => format!("{name} ok {ms}ms"),
        (Some(true), None) => format!("{name} ok"),
        (Some(false), _) => format!("{name} failed"),
        (None, _) => format!("{name} not attempted"),
    };
    format!(
        "{:?}: {}, {}, {}, {}",
        report.state,
        stage("link", report.link.map(|s| s.ok), None),
        stage(
            "gateway",
            report.gateway.map(|s| s.ok),
            report.gateway.and_then(|s| s.ms)
        ),
        stage("dns", report.dns.map(|s| s.ok), report.dns.and_then(|s| s.ms)),
        stage(
            "http",
            report.http.map(|s| s.ok),
            report.http.and_then(|s| s.ms)
        ),
    )
}

fn now() -> String {
    jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string()
}

/// A past instant as local RFC 3339, for the cache stamp in `--json`.
fn local_time(unix: i64) -> String {
    jiff::Timestamp::from_second(unix)
        .map(|stamp| {
            stamp
                .to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string()
        })
        .unwrap_or_else(|_| now())
}

/// The header's local time, with the zone abbreviation the RFC 3339 stamp in
/// the model cannot carry.
fn clock() -> String {
    jiff::Zoned::now().strftime("%H:%M:%S %Z").to_string()
}
