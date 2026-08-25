use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;

use netinspect::cli::{self, Cli, Command};
use netinspect::model::{
    DnsConfig, Exposure, Interface, ListenReport, PublicAddress, Reachability, RoutesReport,
    Snapshot, SocketFilter, SCHEMA,
};
use netinspect::probe::{self, net::Net, Ladder};
use netinspect::public::{self, cache};
use netinspect::render::{human, json, listen as render_listen, routes as render_routes};
use netinspect::sys;
use netinspect::update::{self, check};

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

    match &cli.command {
        Some(Command::Update { force }) => {
            let outcome = update::run(env!("CARGO_PKG_VERSION"), *force, cli.verbose)?;
            println!("netinspect: {}", outcome.message());
            return Ok(match outcome {
                update::Outcome::Updated { .. } | update::Outcome::AlreadyCurrent(_) => {
                    ExitCode::SUCCESS
                }
                // Nothing was installed, and a script should be able to tell.
                _ => ExitCode::from(1),
            });
        }
        Some(Command::Completions { shell }) => {
            use clap::CommandFactory;
            clap_complete::generate(
                *shell,
                &mut Cli::command(),
                "netinspect",
                &mut std::io::stdout(),
            );
            return Ok(ExitCode::SUCCESS);
        }
        _ => {}
    }

    if let Some(Command::Routes { iface }) = &cli.command {
        return routes(&cli, platform.as_ref(), &interfaces, iface.as_deref());
    }
    if let Some(Command::Listen {
        tcp,
        udp,
        exposed,
        port,
        resolve,
    }) = &cli.command
    {
        return listen(
            &cli,
            platform.as_ref(),
            ListenOptions {
                tcp: *tcp,
                udp: *udp,
                exposed: *exposed,
                port: *port,
                resolve: *resolve,
            },
        );
    }

    if matches!(cli.command, Some(Command::Check)) {
        let measured = cli
            .probes_enabled()
            .then(|| measure(&cli, &interfaces, &dns, false))
            .transpose()?;
        return Ok(check(&cli, measured.as_ref().map(|m| &m.0)));
    }

    if let Some(interval) = cli.watch_interval() {
        return watch(&cli, platform.as_ref(), interval);
    }

    let mut carried = Carried {
        update: known_update(),
        ..Carried::default()
    };
    let text = frame(&cli, &interfaces, &dns, &mut carried)?;
    println!("{text}");

    // Never before the report. A first run that paused to ask a server about
    // itself would be a bad first impression, and the answer is only ever used
    // by the *next* run anyway.
    refresh_update_check(&cli);

    // The default command succeeded at its job of reporting, whatever the
    // network turned out to be doing. Only `check` encodes connectivity.
    Ok(ExitCode::SUCCESS)
}

/// What survives from one frame to the next.
#[derive(Default)]
struct Carried {
    /// What the public address was valid for: the route out.
    fingerprint: Option<String>,
    public: Option<PublicAddress>,
    fetched_at_unix: i64,
    /// Whatever the last update check already knew. Never fetched here.
    update: Option<netinspect::model::UpdateInfo>,
}

/// One rendered report.
///
/// The public address is not looked up again every tick — only when the route
/// out has changed. Asking a provider every two seconds where this machine is
/// would be both rude and pointless.
fn frame(
    cli: &Cli,
    interfaces: &[Interface],
    dns: &DnsConfig,
    carried: &mut Carried,
) -> Result<String> {
    let fingerprint = public::fingerprint(interfaces);
    let route_changed = carried.fingerprint.as_deref() != Some(fingerprint.as_str());

    let measured = if cli.probes_enabled() {
        Some(measure(cli, interfaces, dns, route_changed)?)
    } else {
        None
    };
    let (reachability, fetched) = match measured {
        Some((reachability, public)) => (Some(reachability), public),
        None => (None, None),
    };

    let now_unix = jiff::Timestamp::now().as_second();
    if let Some(public) = fetched {
        carried.public = Some(public);
        carried.fetched_at_unix = now_unix;
    }
    carried.fingerprint = Some(fingerprint);

    let age = carried.public.as_ref().and_then(|_| {
        let seconds = now_unix.saturating_sub(carried.fetched_at_unix);
        // Nothing to say about an address measured for this very frame.
        (seconds >= 1).then(|| format!("{} ago", human::duration(seconds as u64)))
    });

    let snapshot = Snapshot {
        schema: SCHEMA,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        timestamp: now(),
        interfaces: interfaces.to_vec(),
        dns: dns.clone(),
        reachability,
        public: carried.public.clone(),
        update: carried.update.clone(),
    };

    if cli.json {
        return json::emit(&snapshot, cli.pretty);
    }
    let mut options = cli.render_options(clock());
    options.public_age = age;
    Ok(human::render(&snapshot, &options).trim_end().to_owned())
}

/// What the last update check found, if it ever ran.
///
/// Read from the cache and nothing else: rendering the footer must not depend
/// on reaching a server.
fn known_update() -> Option<netinspect::model::UpdateInfo> {
    if check::disabled() {
        return None;
    }
    let directory = cache::directory()?;
    check::footer(check::load(&directory).as_ref(), env!("CARGO_PKG_VERSION"))
}

/// Ask about releases at most once a day, after the report is already printed.
///
/// Failures are silent: not knowing about a new version is not something to
/// interrupt anyone over, and a recorded failure keeps it from being retried
/// on every run.
fn refresh_update_check(cli: &Cli) {
    if check::disabled() || cli.json {
        return;
    }
    let Some(directory) = cache::directory() else {
        return;
    };
    let now_unix = jiff::Timestamp::now().as_second();
    let previous = check::load(&directory);
    if !check::due(previous.as_ref(), now_unix) {
        return;
    }

    let latest = latest_release_tag();
    if cli.verbose {
        match &latest {
            Some(tag) => eprintln!("netinspect: update check found {tag}"),
            None => eprintln!("netinspect: update check found nothing"),
        }
    }
    let _ = check::store(
        &directory,
        &check::Check {
            schema: 1,
            checked_at_unix: now_unix,
            latest,
        },
    );
}

fn latest_release_tag() -> Option<String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("netinspect/", env!("CARGO_PKG_VERSION")))
        // Short: the report is already on screen and nobody is waiting for
        // this on purpose.
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;

    runtime.block_on(async {
        let body = client
            .get(update::release::RELEASES_URL)
            .send()
            .await
            .ok()?
            .text()
            .await
            .ok()?;
        update::release::parse(&body)
            .ok()
            .map(|release| release.tag)
    })
}

/// Redraw the frame in place until interrupted.
///
/// Home and clear-to-end rather than the alternate screen: the last frame stays
/// on the terminal after Ctrl-C, which is what a monitoring command is usually
/// wanted for.
fn watch(cli: &Cli, platform: &dyn sys::Platform, interval: Duration) -> Result<ExitCode> {
    let interrupted = sys::interrupt_flag();
    let mut out = std::io::stdout();
    // The cursor would otherwise sit blinking in the middle of the report.
    write!(out, "\x1b[?25l")?;

    let mut carried = Carried {
        update: known_update(),
        ..Carried::default()
    };
    let result = loop {
        let interfaces = match platform.interfaces() {
            Ok(interfaces) => interfaces,
            Err(error) => break Err(error),
        };
        let dns = match platform.dns_config() {
            Ok(dns) => dns,
            Err(error) => break Err(error),
        };
        let text = match frame(cli, &interfaces, &dns, &mut carried) {
            Ok(text) => text,
            Err(error) => break Err(error),
        };

        if let Err(error) = write!(out, "\x1b[H\x1b[J{text}").and_then(|()| out.flush()) {
            break Err(error.into());
        }
        if !wait(interval, interrupted) {
            break Ok(());
        }
    };

    // Whatever happened, give the terminal back.
    let _ = writeln!(out, "\x1b[?25h");
    let _ = out.flush();
    result.map(|()| ExitCode::SUCCESS)
}

/// Sleep in slices so Ctrl-C is answered promptly rather than after the whole
/// interval. Returns false when the user has asked to stop.
fn wait(interval: Duration, interrupted: &std::sync::atomic::AtomicBool) -> bool {
    const SLICE: Duration = Duration::from_millis(50);
    let deadline = Instant::now() + interval;
    while Instant::now() < deadline {
        if interrupted.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(SLICE.min(deadline.saturating_duration_since(Instant::now())));
    }
    !interrupted.load(Ordering::SeqCst)
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

struct ListenOptions {
    tcp: bool,
    udp: bool,
    exposed: bool,
    port: Option<u16>,
    resolve: bool,
}

fn listen(cli: &Cli, platform: &dyn sys::Platform, options: ListenOptions) -> Result<ExitCode> {
    // Neither flag means both; the two together are rejected by clap.
    let both = !options.tcp && !options.udp;
    let mut table = platform.sockets(SocketFilter {
        tcp: both || options.tcp,
        udp: both || options.udp,
        include_established: cli.all,
    })?;

    table.sockets.retain(|socket| {
        options.port.is_none_or(|port| socket.port == port)
            && (!options.exposed || socket.exposure != Exposure::Loopback)
    });
    // The summary describes what is shown.
    let count = |exposure: Exposure| {
        table
            .sockets
            .iter()
            .filter(|s| s.exposure == exposure)
            .count()
    };
    table.summary = netinspect::model::SocketSummary {
        total: table.sockets.len(),
        wildcard: count(Exposure::Wildcard),
        loopback: count(Exposure::Loopback),
        interface: count(Exposure::Interface),
        unattributed: table.sockets.iter().filter(|s| s.process.is_none()).count(),
    };

    let firewall = platform.firewall()?;

    let text = if cli.json {
        json::emit(
            &ListenReport {
                schema: SCHEMA,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                timestamp: now(),
                sockets: table.sockets,
                socket_summary: table.summary,
                firewall,
            },
            cli.pretty,
        )?
    } else {
        render_listen::render(
            &table,
            firewall,
            &render_listen::Options {
                theme: cli.theme(),
                edge: cli.content_edge(),
                current_uid: Some(sys::current_uid()),
                resolve: options.resolve,
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
    lookup: bool,
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
    let may_look_up = lookup && cli.lookup_enabled();
    let cached = stored
        .as_ref()
        .filter(|cache| may_look_up && cache::is_fresh(cache, &fingerprint, now_unix));
    if cli.verbose {
        eprintln!(
            "netinspect: geo cache {}",
            match (&cached, may_look_up) {
                (Some(cache), _) => format!("hit, {}s old", now_unix - cache.fetched_at_unix),
                (None, true) => "miss".to_owned(),
                (None, false) => "not consulted, lookup disabled".to_owned(),
            }
        );
    }

    let pending = match (may_look_up, cached.is_some()) {
        (true, false) => {
            let net = Arc::clone(&net);
            let endpoint = public::endpoint();
            let timeout = cli.probe_timeout();
            Some(
                runtime
                    .spawn(async move { public::lookup(net.as_ref(), &endpoint, timeout).await }),
            )
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
        stage(
            "dns",
            report.dns.map(|s| s.ok),
            report.dns.and_then(|s| s.ms)
        ),
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
