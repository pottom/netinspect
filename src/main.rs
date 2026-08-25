use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use netinspect::cli::{Cli, Command};
use netinspect::model::{Reachability, Snapshot, SCHEMA};
use netinspect::probe::{self, net::Net, Ladder};
use netinspect::render::{human, json};
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

    let reachability = if cli.probes_enabled() {
        Some(measure(&cli, &interfaces, &dns)?)
    } else {
        None
    };

    if matches!(cli.command, Some(Command::Check)) {
        return Ok(check(&cli, reachability.as_ref()));
    }

    let snapshot = Snapshot {
        schema: SCHEMA,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        timestamp: now(),
        interfaces,
        dns,
        reachability,
        public: None,
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

fn measure(
    cli: &Cli,
    interfaces: &[netinspect::model::Interface],
    dns: &netinspect::model::DnsConfig,
) -> Result<Reachability> {
    let net = Net::new()?;
    let ladder = Ladder {
        connector: &net,
        resolver: &net,
        http: &net,
        timeout: cli.probe_timeout(),
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let started = std::time::Instant::now();
    let report = runtime.block_on(ladder.run(interfaces, dns));
    if cli.verbose {
        eprintln!(
            "netinspect: reachability ladder finished in {} ms",
            started.elapsed().as_millis()
        );
    }
    Ok(report)
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

/// The header's local time, with the zone abbreviation the RFC 3339 stamp in
/// the model cannot carry.
fn clock() -> String {
    jiff::Zoned::now().strftime("%H:%M:%S %Z").to_string()
}
