use anyhow::Result;
use clap::Parser;

use netinspect::cli::Cli;
use netinspect::model::{Snapshot, SCHEMA};
use netinspect::render::{human, json};
use netinspect::sys;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let snapshot = collect(&cli)?;

    let text = if cli.json {
        json::emit(&snapshot, cli.pretty)?
    } else {
        human::render(&snapshot, &cli.render_options(clock()))
            .trim_end()
            .to_owned()
    };

    println!("{text}");
    Ok(())
}

fn collect(cli: &Cli) -> Result<Snapshot> {
    let platform = sys::platform(sys::PlatformConfig {
        helpers: cli.helper_policy(),
    });

    Ok(Snapshot {
        schema: SCHEMA,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        timestamp: now(),
        interfaces: platform.interfaces()?,
        dns: platform.dns_config()?,
        reachability: None,
        public: None,
        update: None,
    })
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
