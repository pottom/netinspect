//! Argument parsing and the environment that shapes the report.
//!
//! Flags win over environment variables.

use clap::{Parser, Subcommand};

use std::time::Duration;

use crate::render::theme::{ColorMode, Palette, Theme, ASCII, UNICODE};

const GEO_PROVIDER_NOTE: &str = "\
The public-address lookup sends this machine's IP to ipinfo.io
(https://ipinfo.io/privacy). Set NETINSPECT_NO_LOOKUP=1 to disable it
machine-wide. Nothing else leaves the machine: no telemetry, no crash
reporting.";

#[derive(Debug, Parser)]
#[command(
    name = "netinspect",
    version,
    about = "Read-only network diagnostics: configuration, reachability, public address",
    after_help = GEO_PROVIDER_NOTE
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Restrict the interface section to one interface (e.g. en0, utun3)
    pub interface: Option<String>,

    /// Emit JSON instead of the human report. Implies --no-color
    #[arg(short = 'j', long, global = true)]
    pub json: bool,

    /// Indent JSON output
    #[arg(long, global = true, requires = "json")]
    pub pretty: bool,

    /// Show everything: inactive and loopback interfaces in full detail, and
    /// the cloned, multicast and link-local entries `routes` hides
    #[arg(short = 'a', long, global = true)]
    pub all: bool,

    /// Suppress IPv6
    #[arg(short = '4', long = "ipv4-only", global = true, conflicts_with = "ipv6_only")]
    pub ipv4_only: bool,

    /// Suppress IPv4
    #[arg(short = '6', long = "ipv6-only", global = true)]
    pub ipv6_only: bool,

    /// Disable the SSID helper ladder. No subprocess is spawned
    #[arg(long, global = true)]
    pub no_helpers: bool,

    /// Allow the system_profiler SSID candidate, which takes seconds
    #[arg(long, global = true, conflicts_with = "no_helpers")]
    pub slow_helpers: bool,

    /// Never emit ANSI sequences
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Use the ASCII fallback glyph set
    #[arg(long, global = true)]
    pub ascii: bool,

    /// Palette to render with. Detected from the terminal background by default
    #[arg(long, global = true, value_name = "PALETTE",
          value_parser = ["dark", "dark-warm", "light", "light-warm"])]
    pub theme: Option<String>,

    /// Skip the public-address lookup. No outbound request for geo
    #[arg(long, global = true)]
    pub no_lookup: bool,

    /// Skip the reachability probes
    #[arg(long, global = true)]
    pub no_check: bool,

    /// Per-probe timeout in milliseconds
    #[arg(long, global = true, value_name = "MS", default_value_t = 2000)]
    pub timeout: u64,

    /// Log probe timing and cache decisions to stderr
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the routing table
    Routes {
        /// Only routes whose output interface matches
        #[arg(long, value_name = "NAME")]
        iface: Option<String>,
    },
    /// Report connectivity through the exit code alone. Prints nothing on
    /// success unless -v is given.
    ///
    /// Exit codes: 0 online, 10 link down, 11 gateway unreachable,
    /// 12 dns failure, 13 captive portal.
    Check,
}

impl Cli {
    /// Whether the reachability ladder should run at all. Only the default
    /// report and `check` have any use for it.
    pub fn probes_enabled(&self) -> bool {
        match self.command {
            Some(Command::Check) => true,
            Some(Command::Routes { .. }) => false,
            None => !self.no_check,
        }
    }

    /// Which address family the routing table is asked for.
    pub fn family(&self) -> Option<crate::model::Family> {
        match (self.ipv4_only, self.ipv6_only) {
            (true, false) => Some(crate::model::Family::Inet),
            (false, true) => Some(crate::model::Family::Inet6),
            _ => None,
        }
    }

    /// Whether this run may tell the provider anything. `check` never does:
    /// it answers from the exit code and has no use for a location.
    pub fn lookup_enabled(&self) -> bool {
        !self.no_lookup
            && self.command.is_none()
            && !crate::public::lookup_disabled()
    }

    pub fn probe_timeout(&self) -> std::time::Duration {
        Duration::from_millis(self.timeout.clamp(50, 30_000))
    }

    pub fn helper_policy(&self) -> crate::sys::HelperPolicy {
        use crate::sys::HelperPolicy;
        if self.no_helpers || env_flag("NETINSPECT_NO_HELPERS") {
            HelperPolicy::Disabled
        } else if self.slow_helpers {
            HelperPolicy::Slow
        } else {
            HelperPolicy::Fast
        }
    }

    pub fn theme(&self) -> Theme {
        let color = self.color_mode();
        Theme {
            color,
            palette: self.palette(color),
            glyphs: if self.ascii || !terminal_is_utf8() {
                ASCII
            } else {
                UNICODE
            },
        }
    }

    fn color_mode(&self) -> ColorMode {
        // NO_COLOR is an informal standard: any value disables colour.
        if self.no_color || self.json || std::env::var_os("NO_COLOR").is_some() {
            return ColorMode::None;
        }
        match supports_color::on(supports_color::Stream::Stdout) {
            Some(support) if support.has_16m => ColorMode::TrueColor,
            Some(support) if support.has_256 => ColorMode::Ansi256,
            // 8/16 colour still carries the reach triple as blue/cyan/yellow;
            // that is why those hues were chosen over three bespoke ones.
            Some(support) if support.has_basic => ColorMode::Ansi16,
            _ => ColorMode::None,
        }
    }

    /// Terminals do not announce their background, so: an explicit choice, then
    /// the OSC 11 query, then `COLORFGBG`, then dark.
    fn palette(&self, color: ColorMode) -> Palette {
        if let Some(name) = self.theme.as_deref() {
            if let Some(palette) = Palette::parse(name) {
                return palette;
            }
        }
        if let Some(palette) = std::env::var("NETINSPECT_THEME")
            .ok()
            .and_then(|v| Palette::parse(&v))
        {
            return palette;
        }
        if color == ColorMode::None {
            return Palette::Dark;
        }
        detect_palette().unwrap_or(Palette::Dark)
    }

    /// Where everything right-aligned lands, for the renderers that do not
    /// take a full `human::Options`.
    pub fn content_edge(&self) -> usize {
        crate::render::layout::content_edge(self.width())
    }

    /// Everything the human renderer needs from the command line. `clock` is
    /// the preformatted local time for the header; the renderer stays pure and
    /// never reads the system clock itself.
    pub fn render_options(&self, clock: String) -> crate::render::human::Options {
        crate::render::human::Options {
            theme: self.theme(),
            width: self.width(),
            clock,
            all: self.all,
            ipv4_only: self.ipv4_only,
            ipv6_only: self.ipv6_only,
            only_interface: self.interface.clone(),
            system_timezone: system_timezone(),
            edge: None,
        }
    }

    /// Terminal width. `COLUMNS` wins when it is set, as it does for most
    /// tools, so the layout can be exercised without a terminal; otherwise the
    /// real width, falling back to 80 when stdout is not a terminal so piped
    /// output stays stable.
    pub fn width(&self) -> usize {
        if let Some(columns) = std::env::var("COLUMNS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|w| *w > 0)
        {
            return columns;
        }
        terminal_size::terminal_size()
            .map(|(terminal_size::Width(w), _)| w as usize)
            .unwrap_or(80)
    }
}

/// Ask the terminal what colour it is painted, then fall back to the variable
/// some terminals set instead. Both are best-effort and neither is allowed to
/// delay the report.
fn detect_palette() -> Option<Palette> {
    if let Ok(rgb) = termbg::rgb(Duration::from_millis(100)) {
        // termbg reports 16 bits per channel.
        let (r, g, b) = (
            (rgb.r >> 8) as u8,
            (rgb.g >> 8) as u8,
            (rgb.b >> 8) as u8,
        );
        return Some(palette_for_background(r, g, b));
    }
    palette_from_colorfgbg()
}

/// `COLORFGBG` is `foreground;background` as ANSI colour indices. Only the
/// background half matters, and only whether it is dark.
fn palette_from_colorfgbg() -> Option<Palette> {
    let value = std::env::var("COLORFGBG").ok()?;
    let background: u8 = value.rsplit(';').next()?.trim().parse().ok()?;
    Some(match background {
        0..=6 | 8 => Palette::Dark,
        _ => Palette::Light,
    })
}

/// Lightness picks the family; a warm cast picks the variant. The warm palettes
/// exist because Solarized and the various sepia themes shift every neutral,
/// and a palette tuned on neutral grey goes muddy on them.
///
/// Warmth is measured relative to the background's own brightness, not as an
/// absolute channel difference: a near-black sepia terminal separates red from
/// blue by a handful of levels, while an off-white one can differ by that much
/// and still read as neutral paper.
fn palette_for_background(r: u8, g: u8, b: u8) -> Palette {
    let luminance = (0.2126 * r as f64 + 0.7152 * g as f64 + 0.0722 * b as f64) / 255.0;
    let peak = r.max(g).max(b).max(1) as f64;
    let warm = (r as f64 - b as f64) / peak >= 0.06;
    match (luminance < 0.5, warm) {
        (true, false) => Palette::Dark,
        (true, true) => Palette::DarkWarm,
        (false, false) => Palette::Light,
        (false, true) => Palette::LightWarm,
    }
}

/// The machine's own IANA zone, when it has a name. A fixed offset does not.
pub fn system_timezone() -> Option<String> {
    jiff::tz::TimeZone::system()
        .iana_name()
        .map(str::to_owned)
}

fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1") | Ok("true"))
}

/// The ASCII fallback also triggers automatically when the locale does not
/// indicate UTF-8, because the glyphs would otherwise render as replacement
/// characters and shift every column.
fn terminal_is_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .find(|value| !value.is_empty())
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("utf-8") || value.contains("utf8")
        })
        // No locale set at all: assume the modern default rather than
        // downgrading every terminal to ASCII.
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn json_implies_no_color() {
        let cli = Cli::parse_from(["netinspect", "--json"]);
        assert_eq!(cli.color_mode(), ColorMode::None);
    }

    #[test]
    fn address_family_flags_are_exclusive() {
        assert!(Cli::try_parse_from(["netinspect", "-4", "-6"]).is_err());
        assert!(Cli::try_parse_from(["netinspect", "--no-helpers", "--slow-helpers"]).is_err());
        // --pretty without --json is a usage error, not a silent no-op.
        assert!(Cli::try_parse_from(["netinspect", "--pretty"]).is_err());
    }

    #[test]
    fn backgrounds_choose_a_palette() {
        // Near-black neutral, the default terminal.
        assert_eq!(palette_for_background(0x0E, 0x0E, 0x11), Palette::Dark);
        // Solarized dark is blue-cast, so it stays on the neutral dark palette.
        assert_eq!(palette_for_background(0x00, 0x2B, 0x36), Palette::Dark);
        // A sepia dark terminal.
        assert_eq!(palette_for_background(0x1C, 0x19, 0x17), Palette::DarkWarm);
        assert_eq!(palette_for_background(0xFA, 0xF8, 0xF3), Palette::Light);
        // Solarized light is distinctly warm.
        assert_eq!(palette_for_background(0xFD, 0xF6, 0xE3), Palette::LightWarm);
    }

    #[test]
    fn an_explicit_theme_beats_detection() {
        let cli = Cli::parse_from(["netinspect", "--theme", "light-warm"]);
        assert_eq!(cli.palette(ColorMode::TrueColor), Palette::LightWarm);
        // An unknown palette name is rejected by clap, not silently ignored.
        assert!(Cli::try_parse_from(["netinspect", "--theme", "neon"]).is_err());
    }

    #[test]
    fn positional_interface_is_optional() {
        assert_eq!(Cli::parse_from(["netinspect"]).interface, None);
        assert_eq!(
            Cli::parse_from(["netinspect", "en0"]).interface.as_deref(),
            Some("en0")
        );
    }

    #[test]
    fn every_subcommand_can_emit_json() {
        // A flag that only parses before the subcommand is a flag nobody finds.
        assert!(Cli::parse_from(["netinspect", "routes", "--json"]).json);
        assert!(Cli::parse_from(["netinspect", "routes", "-j", "--pretty"]).pretty);
        // And --pretty without --json is still a usage error, wherever it sits.
        assert!(Cli::try_parse_from(["netinspect", "routes", "--pretty"]).is_err());
    }

    #[test]
    fn routes_takes_the_global_family_flags() {
        let cli = Cli::parse_from(["netinspect", "routes", "-6", "--all"]);
        assert!(matches!(cli.command, Some(Command::Routes { iface: None })));
        assert_eq!(cli.family(), Some(crate::model::Family::Inet6));
        assert!(cli.all);
        // And it never probes: a routing table needs no network.
        assert!(!cli.probes_enabled());

        let scoped = Cli::parse_from(["netinspect", "routes", "--iface", "utun4"]);
        assert!(matches!(
            scoped.command,
            Some(Command::Routes { iface: Some(ref name) }) if name == "utun4"
        ));
    }

    #[test]
    fn check_is_a_subcommand_not_an_interface_name() {
        let cli = Cli::parse_from(["netinspect", "check"]);
        assert!(matches!(cli.command, Some(Command::Check)));
        assert_eq!(cli.interface, None);
    }

    #[test]
    fn check_never_reaches_the_provider() {
        // It answers through an exit code; a location would be a disclosure
        // with nothing asking for it.
        assert!(!Cli::parse_from(["netinspect", "check"]).lookup_enabled());
        assert!(Cli::parse_from(["netinspect"]).lookup_enabled());
        assert!(!Cli::parse_from(["netinspect", "--no-lookup"]).lookup_enabled());
    }

    #[test]
    fn global_flags_reach_the_subcommand() {
        // `netinspect check -v` has to work; a flag that only parses before the
        // subcommand is a flag nobody will find.
        let cli = Cli::parse_from(["netinspect", "check", "-v", "--timeout", "800"]);
        assert!(cli.verbose);
        assert_eq!(cli.timeout, 800);
    }

    #[test]
    fn check_probes_even_with_no_check() {
        // `--no-check` suppresses the report's reachability section; asking
        // `check` for a verdict and then not measuring one would be absurd.
        let cli = Cli::parse_from(["netinspect", "check", "--no-check"]);
        assert!(cli.probes_enabled());
        assert!(!Cli::parse_from(["netinspect", "--no-check"]).probes_enabled());
        assert!(Cli::parse_from(["netinspect"]).probes_enabled());
    }

    #[test]
    fn the_timeout_is_clamped_to_something_survivable() {
        assert_eq!(
            Cli::parse_from(["netinspect"]).probe_timeout(),
            Duration::from_millis(2000)
        );
        assert_eq!(
            Cli::parse_from(["netinspect", "--timeout", "0"]).probe_timeout(),
            Duration::from_millis(50)
        );
        assert_eq!(
            Cli::parse_from(["netinspect", "--timeout", "999999"]).probe_timeout(),
            Duration::from_millis(30_000)
        );
    }
}
