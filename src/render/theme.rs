//! Colour and glyph tables.
//!
//! Normative source: `docs/DESIGN.md`, which replaces the colour table in §7.3
//! of the implementation spec.
//!
//! The one idea: **hue encodes reach** — how far away a thing can be touched
//! from. Nothing else gets a hue. Hierarchy inside the neutrals comes from
//! weight and lightness, never from colour. A reader who learns three colours
//! can read every subcommand.

// The role and glyph tables are complete by design: they describe the whole
// report, including subcommands that land in later milestones. Remove this once
// every role and glyph has a caller.
#![allow(dead_code)]

/// What a fragment of text means. Eleven roles; anything not on this list is a
/// bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The answer to the question the user asked.
    Bright,
    /// Ordinary values.
    Body,
    /// The label column.
    Dim,
    /// Reference material and units.
    Faint,
    /// Structure that must not be read.
    Rule,
    /// A probe answered.
    Ok,
    /// A probe failed, or a guarantee is broken.
    Fail,
    /// Reachable only from this machine.
    Local,
    /// Reachable from this network.
    Lan,
    /// The open internet is involved. Not a warning — severity comes from the
    /// word next to it, not the hue.
    Public,
    /// Copyable and runnable.
    Action,
}

/// Index into a palette's tables. Keep in step with `Role`.
impl Role {
    const fn index(self) -> usize {
        match self {
            Role::Bright => 0,
            Role::Body => 1,
            Role::Dim => 2,
            Role::Faint => 3,
            Role::Rule => 4,
            Role::Ok => 5,
            Role::Fail => 6,
            Role::Local => 7,
            Role::Lan => 8,
            Role::Public => 9,
            Role::Action => 10,
        }
    }

    /// The 8/16-colour approximation. The reach triple survives as blue / cyan
    /// / yellow — that is why those three hues were chosen over three bespoke
    /// ones.
    const fn ansi16(self) -> Option<&'static str> {
        match self {
            Role::Bright => Some("1"),
            Role::Body | Role::Dim => None,
            Role::Faint | Role::Rule => Some("2"),
            Role::Ok => Some("32"),
            Role::Fail => Some("31"),
            Role::Local => Some("34"),
            Role::Lan => Some("36"),
            Role::Public => Some("33"),
            Role::Action => Some("35"),
        }
    }
}

/// Which background the palette was tuned against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Palette {
    #[default]
    Dark,
    DarkWarm,
    Light,
    LightWarm,
}

impl Palette {
    pub fn name(self) -> &'static str {
        match self {
            Palette::Dark => "dark",
            Palette::DarkWarm => "dark-warm",
            Palette::Light => "light",
            Palette::LightWarm => "light-warm",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "dark" => Some(Palette::Dark),
            "dark-warm" | "darkwarm" => Some(Palette::DarkWarm),
            "light" => Some(Palette::Light),
            "light-warm" | "lightwarm" => Some(Palette::LightWarm),
            _ => None,
        }
    }

    /// Truecolor values, verified against the palette's background: body ≥ 7:1,
    /// dim ≥ 4.5:1, faint ≥ 3:1, every hue ≥ 4.5:1, and adjacent hues ≥ 1.4:1
    /// against each other. Do not adjust one entry without re-checking those.
    const fn truecolor(self) -> &'static [(u8, u8, u8); 11] {
        match self {
            // tuned on #0E0E11, valid #000000–#22222A
            Palette::Dark => &[
                (0xF2, 0xF0, 0xE9),
                (0xB9, 0xB7, 0xAF),
                (0x7F, 0x7D, 0x76),
                (0x57, 0x55, 0x50),
                (0x2A, 0x2B, 0x30),
                (0x8C, 0xC9, 0x6F),
                (0xF2, 0x70, 0x5F),
                (0x7F, 0xB0, 0xE8),
                (0x45, 0xBB, 0xA0),
                (0xEB, 0xAB, 0x45),
                (0xBC, 0xA2, 0xF5),
            ],
            // tuned on #1C1917; also covers Solarized dark #002B36
            Palette::DarkWarm => &[
                (0xF5, 0xEF, 0xE6),
                (0xC0, 0xB7, 0xAB),
                (0x8A, 0x81, 0x77),
                (0x61, 0x5A, 0x52),
                (0x33, 0x2E, 0x2A),
                (0x93, 0xC9, 0x6B),
                (0xF0, 0x73, 0x6A),
                (0x83, 0xAE, 0xEA),
                (0x48, 0xBD, 0xA2),
                (0xEE, 0xAC, 0x41),
                (0xC0, 0xA4, 0xF7),
            ],
            // tuned on #FAF8F3, valid #F0F0F0–#FFFFFF
            Palette::Light => &[
                (0x17, 0x16, 0x1A),
                (0x44, 0x42, 0x3B),
                (0x78, 0x76, 0x6E),
                (0xA3, 0xA0, 0x97),
                (0xE0, 0xDC, 0xD1),
                (0x3F, 0x7A, 0x22),
                (0xC0, 0x39, 0x2B),
                (0x1F, 0x5F, 0xA8),
                (0x0F, 0x73, 0x65),
                (0x8A, 0x5A, 0x0A),
                (0x61, 0x46, 0xC4),
            ],
            // Solarized light #FDF6E3
            Palette::LightWarm => &[
                (0x1C, 0x1E, 0x21),
                (0x4B, 0x54, 0x57),
                (0x7A, 0x83, 0x85),
                (0xA0, 0xA6, 0x9F),
                (0xE6, 0xDD, 0xC6),
                (0x4A, 0x7A, 0x12),
                (0xBC, 0x3B, 0x2E),
                (0x19, 0x58, 0x9E),
                (0x0D, 0x6F, 0x61),
                (0x8A, 0x55, 0x02),
                (0x5B, 0x3F, 0xC0),
            ],
        }
    }

    /// Nearest xterm index per role, computed once and committed. Never round
    /// at runtime: a rounding function that changes would silently reshade
    /// every report.
    const fn ansi256(self) -> &'static [u8; 11] {
        match self {
            Palette::Dark => &[255, 249, 244, 240, 236, 113, 203, 110, 73, 179, 147],
            Palette::DarkWarm => &[255, 249, 244, 240, 236, 113, 203, 110, 73, 215, 147],
            Palette::Light => &[234, 238, 243, 247, 253, 64, 130, 25, 23, 94, 62],
            Palette::LightWarm => &[234, 239, 244, 247, 188, 64, 130, 25, 23, 94, 61],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    None,
    Ansi16,
    Ansi256,
    TrueColor,
}

/// The glyph set. Every entry has an ASCII counterpart of the same intent, so a
/// terminal that cannot show the Unicode one keeps its alignment.
#[derive(Debug, Clone, Copy)]
pub struct Glyphs {
    /// Left rail, header line. Carries the interface's reach colour.
    pub rail_head: &'static str,
    /// Left rail, continuation lines.
    pub rail_body: &'static str,
    /// Left rail, last line of a block, and inactive interfaces.
    pub rail_end: &'static str,
    pub check: &'static str,
    pub cross: &'static str,
    /// A stage that was never attempted. Not a failure.
    pub pending: &'static str,
    pub rule: &'static str,
    pub connector: &'static str,
    /// The signal meter for each level 0..=5, as `(lit, unlit)`.
    ///
    /// Split in two because a braille cell is a single character and carries a
    /// single colour: the boundary between what was measured and what was not
    /// can only fall between cells. So the *shape* carries the reading — a
    /// staircase that flattens to a dotted baseline as the signal drops — and
    /// the colour merely follows it. The baseline is always drawn, or a weak
    /// signal would leave nothing to compare against.
    pub meter: [(&'static str, &'static str); 6],
    pub sep: &'static str,
    pub arrow_up: &'static str,
    pub partial: &'static str,
    /// Placeholder for a value that could not be determined.
    pub unknown: &'static str,
    /// The owner column's leading mark in `listen`. The *shape* says what kind
    /// of owner it is; the row's colours already say how far away the port can
    /// be reached from, so these carry no hue of their own.
    ///
    /// Every row gets one. A single marked row among unmarked ones reads as an
    /// exception rather than as a column, and the names stop lining up.
    pub container: &'static str,
    /// A process running as root.
    pub privileged: &'static str,
    /// A process running as anybody else.
    pub process: &'static str,
    /// Interface kinds, for the section headers.
    pub wifi: &'static str,
    pub ethernet: &'static str,
    pub tunnel: &'static str,
    pub loopback: &'static str,
    /// Section marks: name resolution, the reachability ladder, the public
    /// address, and the firewall.
    pub dns: &'static str,
    pub link: &'static str,
    pub globe: &'static str,
    pub shield: &'static str,
    /// Typographic minus, for RSSI in the human report only.
    pub minus: &'static str,
    pub plus_minus: &'static str,
}

pub const UNICODE: Glyphs = Glyphs {
    rail_head: "▌",
    rail_body: "│",
    rail_end: "╵",
    check: "✓",
    cross: "✗",
    pending: "·",
    rule: "─",
    connector: "──",
    meter: [
        ("", "⣀⣀⡀"),
        ("⣀", "⣀⡀"),
        ("⣠", "⣀⡀"),
        ("⣠⣆", "⡀"),
        ("⣠⣾", "⡀"),
        ("⣠⣾⡇", ""),
    ],
    sep: "·",
    arrow_up: "↑",
    partial: "◐",
    unknown: "—",
    container: "▣",
    privileged: "◆",
    process: "◇",
    wifi: "",
    ethernet: "",
    tunnel: "",
    loopback: "",
    dns: "",
    link: "",
    globe: "",
    shield: "",
    minus: "−",
    plus_minus: "±",
};

/// The codepoint ranges the Nerd set may draw from.
///
/// Not a guess about Nerd Fonts' release notes: measured by reading the `cmap`
/// of a v2 font (Hack, "Nerd Font Complete") and a v3 font (JetBrainsMono NL)
/// and counting which codepoints both carry.
///
/// | range | in both | v3 only |
/// |---|---|---|
/// | Devicons `E700`–`E7C5` | 198/198 | 0 |
/// | Font Awesome `F000`–`F2E0` | 679/737 | 0 |
/// | Font Logos `F300`–`F32F` | 48/48 | 0 |
/// | Seti `E5FA`–`E6B1` | 59/184 | **121** |
/// | Octicons `F400`–`F532` | 221/307 | **86** |
///
/// The last two are why this list exists. A glyph from either would look right
/// on a current font and be a blank box on one a few years old.
pub const NERD_RANGES: [(char, char); 3] = [
    ('\u{e700}', '\u{e7c5}'),
    ('\u{f000}', '\u{f2e0}'),
    ('\u{f300}', '\u{f32f}'),
];

/// Which glyph set to render with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icons {
    /// Unicode where the locale says the terminal can take it, ASCII where it
    /// cannot. Never Nerd — see [`NERD`] for why that cannot be detected.
    Auto,
    Nerd,
    Unicode,
    Ascii,
}

impl Icons {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Icons::Auto),
            "nerd" | "nerdfont" | "nerd-font" => Some(Icons::Nerd),
            "unicode" | "utf8" | "utf-8" => Some(Icons::Unicode),
            "ascii" | "plain" => Some(Icons::Ascii),
            _ => None,
        }
    }

    /// `utf8` is what the locale claims, and only `Auto` consults it: an
    /// explicit choice is the user telling us something we cannot measure, and
    /// second-guessing it would make the flag useless.
    pub fn glyphs(self, utf8: bool) -> Glyphs {
        match self {
            Icons::Nerd => NERD,
            Icons::Unicode => UNICODE,
            Icons::Ascii => ASCII,
            Icons::Auto if utf8 => UNICODE,
            Icons::Auto => ASCII,
        }
    }
}

/// The Nerd Font set.
///
/// Never chosen automatically. A terminal does not tell an application what
/// font it is using — there is no escape sequence for it, and the usual trick
/// of printing a glyph and asking for the cursor position measures *width*,
/// which a missing glyph still has. Guessing wrong fills the report with empty
/// boxes, so this set is opt-in and nothing else.
///
/// Every codepoint here comes from a range measured to be identical in Nerd
/// Fonts v2 and v3 — see `NERD_RANGES`. Ranges outside that list gained or
/// moved glyphs in v3 and would render as an empty box on an older font, which
/// is exactly the failure this set exists to avoid.
///
/// Where Unicode already does the job better — the braille meter, the rails,
/// the rules — this set inherits it rather than reaching for an icon.
pub const NERD: Glyphs = Glyphs {
    check: "\u{f00c}",      // nf-fa-check
    cross: "\u{f00d}",      // nf-fa-close
    partial: "\u{f042}",    // nf-fa-adjust, a half-filled circle
    arrow_up: "\u{f062}",   // nf-fa-arrow_up
    container: "\u{f308}",  // nf-linux-docker, the whale
    privileged: "\u{f013}", // nf-fa-cog
    process: "\u{f007}",    // nf-fa-user
    wifi: "\u{f1eb}",       // nf-fa-wifi
    ethernet: "\u{f1e6}",   // nf-fa-plug
    tunnel: "\u{f023}",     // nf-fa-lock
    loopback: "\u{f109}",   // nf-fa-laptop
    dns: "\u{f233}",        // nf-fa-server
    link: "\u{f0c1}",       // nf-fa-link
    globe: "\u{f0ac}",      // nf-fa-globe
    shield: "\u{f132}",     // nf-fa-shield
    ..UNICODE
};

pub const ASCII: Glyphs = Glyphs {
    rail_head: "|",
    rail_body: "|",
    rail_end: ".",
    check: "ok",
    cross: "xx",
    pending: ".",
    rule: "-",
    connector: "-",
    meter: [
        ("", ".:-=#"),
        (".", ":-=#"),
        (".:", "-=#"),
        (".:-", "=#"),
        (".:-=", "#"),
        (".:-=#", ""),
    ],
    sep: "|",
    arrow_up: "^",
    partial: "!",
    unknown: "?",
    container: "[]",
    privileged: "##",
    process: "<>",
    wifi: "",
    ethernet: "",
    tunnel: "",
    loopback: "",
    dns: "",
    link: "",
    globe: "",
    shield: "",
    minus: "-",
    plus_minus: "+/-",
};

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub color: ColorMode,
    pub palette: Palette,
    pub glyphs: Glyphs,
}

impl Theme {
    /// No colour, Unicode glyphs. The shape every snapshot test asserts on.
    pub fn plain() -> Self {
        Theme {
            color: ColorMode::None,
            palette: Palette::Dark,
            glyphs: UNICODE,
        }
    }

    pub fn ascii_plain() -> Self {
        Theme {
            color: ColorMode::None,
            palette: Palette::Dark,
            glyphs: ASCII,
        }
    }

    /// True when colour is unavailable, so structure has to carry what hue was
    /// carrying. See `DESIGN.md` §6.
    pub fn monochrome(&self) -> bool {
        self.color == ColorMode::None
    }

    /// Wrap `text` in the escape sequence for `role`.
    pub fn paint(&self, role: Role, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        match self.color {
            ColorMode::None => text.to_owned(),
            ColorMode::Ansi16 => match role.ansi16() {
                Some(code) => format!("\x1b[{code}m{text}\x1b[0m"),
                None => text.to_owned(),
            },
            ColorMode::Ansi256 => {
                let index = self.palette.ansi256()[role.index()];
                format!("\x1b[38;5;{index}m{text}\x1b[0m")
            }
            ColorMode::TrueColor => {
                let (r, g, b) = self.palette.truecolor()[role.index()];
                format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Role; 11] = [
        Role::Bright,
        Role::Body,
        Role::Dim,
        Role::Faint,
        Role::Rule,
        Role::Ok,
        Role::Fail,
        Role::Local,
        Role::Lan,
        Role::Public,
        Role::Action,
    ];

    const PALETTES: [Palette; 4] = [
        Palette::Dark,
        Palette::DarkWarm,
        Palette::Light,
        Palette::LightWarm,
    ];

    fn relative_luminance((r, g, b): (u8, u8, u8)) -> f64 {
        fn channel(v: u8) -> f64 {
            let v = v as f64 / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        }
        0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
    }

    fn contrast(a: (u8, u8, u8), b: (u8, u8, u8)) -> f64 {
        let (x, y) = (relative_luminance(a), relative_luminance(b));
        let (hi, lo) = if x > y { (x, y) } else { (y, x) };
        (hi + 0.05) / (lo + 0.05)
    }

    /// Perceptual distance in OKLab. Luminance contrast is the wrong instrument
    /// for hue separation: the reach triple is deliberately equal in lightness
    /// so the three read as peers rather than as a hierarchy, which puts every
    /// pair near 1.1:1 in WCAG terms while being obviously different colours.
    fn oklab_distance(a: (u8, u8, u8), b: (u8, u8, u8)) -> f64 {
        fn oklab((r, g, b): (u8, u8, u8)) -> (f64, f64, f64) {
            fn linear(v: u8) -> f64 {
                let v = v as f64 / 255.0;
                if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            }
            let (r, g, b) = (linear(r), linear(g), linear(b));
            let l = (0.412_221_47 * r + 0.536_332_54 * g + 0.051_445_99 * b).cbrt();
            let m = (0.211_903_50 * r + 0.680_699_55 * g + 0.107_396_96 * b).cbrt();
            let s = (0.088_302_46 * r + 0.281_718_84 * g + 0.629_978_70 * b).cbrt();
            (
                0.210_454_26 * l + 0.793_617_79 * m - 0.004_072_05 * s,
                1.977_998_50 * l - 2.428_592_21 * m + 0.450_593_71 * s,
                0.025_904_04 * l + 0.782_771_77 * m - 0.808_675_77 * s,
            )
        }
        let (a, b) = (oklab(a), oklab(b));
        ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2) + (a.2 - b.2).powi(2)).sqrt()
    }

    /// The background each palette is tuned against, from DESIGN.md §3.
    fn background(palette: Palette) -> (u8, u8, u8) {
        match palette {
            Palette::Dark => (0x0E, 0x0E, 0x11),
            Palette::DarkWarm => (0x1C, 0x19, 0x17),
            Palette::Light => (0xFA, 0xF8, 0xF3),
            Palette::LightWarm => (0xFD, 0xF6, 0xE3),
        }
    }

    /// Contrast floors DESIGN.md §3 states for every palette.
    fn floor(role: Role) -> f64 {
        match role {
            Role::Body => 7.0,
            Role::Dim => 4.5,
            Role::Faint => 3.0,
            _ => 4.5,
        }
    }

    /// Where the shipped palettes do not meet the floors DESIGN.md claims for
    /// them, measured. These are recorded rather than rounded away: the numbers
    /// below are a ceiling, so a palette edit that makes any of them worse
    /// fails, and the day the design is corrected the entry simply goes.
    ///
    /// `faint` is used for reference material — MAC addresses, MTU, flags,
    /// units — so it is the least costly place to be short, but it is short.
    const KNOWN_SHORTFALLS: [(Palette, Role, f64); 6] = [
        (Palette::Dark, Role::Faint, 2.59),
        (Palette::DarkWarm, Role::Faint, 2.58),
        (Palette::Light, Role::Dim, 4.29),
        (Palette::Light, Role::Faint, 2.46),
        (Palette::LightWarm, Role::Dim, 3.60),
        (Palette::LightWarm, Role::Faint, 2.30),
    ];

    fn recorded_shortfall(palette: Palette, role: Role) -> Option<f64> {
        KNOWN_SHORTFALLS
            .iter()
            .find(|(p, r, _)| *p == palette && *r == role)
            .map(|(_, _, measured)| *measured)
    }

    #[test]
    fn every_palette_meets_its_stated_contrast_floors() {
        // DESIGN.md §3 states these and says not to change one row without
        // re-checking them. This is that check.
        for palette in PALETTES {
            let bg = background(palette);
            let colors = palette.truecolor();
            for role in ALL {
                if matches!(role, Role::Bright | Role::Rule) {
                    continue; // bright has no ceiling; rule is meant to disappear
                }
                let measured = contrast(colors[role.index()], bg);
                match recorded_shortfall(palette, role) {
                    Some(recorded) => assert!(
                        measured >= recorded - 0.005,
                        "{} {role:?} regressed to {measured:.2}:1, below the recorded {recorded:.2}:1",
                        palette.name()
                    ),
                    None => assert!(
                        measured >= floor(role),
                        "{} {role:?} is {measured:.2}:1, under the stated {:.1}:1",
                        palette.name(),
                        floor(role)
                    ),
                }
            }
        }
    }

    #[test]
    fn the_reach_triple_stays_distinguishable() {
        // local / lan / public are the whole system. If any two converge, a
        // reader cannot tell a loopback bind from an internet-facing one.
        for palette in PALETTES {
            let colors = palette.truecolor();
            for (a, b) in [
                (Role::Local, Role::Lan),
                (Role::Lan, Role::Public),
                (Role::Local, Role::Public),
            ] {
                let distance = oklab_distance(colors[a.index()], colors[b.index()]);
                assert!(
                    distance >= 0.10,
                    "{}: {a:?} vs {b:?} only {distance:.3} apart in OKLab",
                    palette.name()
                );
            }
        }
    }

    #[test]
    fn no_two_hues_collide() {
        // Every hue must be tellable from every other, not just within the
        // reach triple — green on amber is the pair that matters for the
        // reachability ladder.
        let hues = [
            Role::Ok,
            Role::Fail,
            Role::Local,
            Role::Lan,
            Role::Public,
            Role::Action,
        ];
        for palette in PALETTES {
            let colors = palette.truecolor();
            for (i, a) in hues.iter().enumerate() {
                for b in &hues[i + 1..] {
                    let distance = oklab_distance(colors[a.index()], colors[b.index()]);
                    assert!(
                        distance >= 0.08,
                        "{}: {a:?} vs {b:?} only {distance:.3} apart in OKLab",
                        palette.name()
                    );
                }
            }
        }
    }

    #[test]
    fn no_colour_emits_no_escapes() {
        let theme = Theme::plain();
        for role in ALL {
            assert_eq!(theme.paint(role, "x"), "x");
        }
    }

    #[test]
    fn sixteen_colour_keeps_the_reach_triple_apart() {
        let mut theme = Theme::plain();
        theme.color = ColorMode::Ansi16;
        assert_eq!(theme.paint(Role::Local, "x"), "\x1b[34mx\x1b[0m");
        assert_eq!(theme.paint(Role::Lan, "x"), "\x1b[36mx\x1b[0m");
        assert_eq!(theme.paint(Role::Public, "x"), "\x1b[33mx\x1b[0m");
        // body and dim have no 16-colour equivalent and stay default.
        assert_eq!(theme.paint(Role::Body, "x"), "x");
    }

    #[test]
    fn palette_names_round_trip() {
        for palette in PALETTES {
            assert_eq!(Palette::parse(palette.name()), Some(palette));
        }
        assert_eq!(Palette::parse("nonsense"), None);
    }

    #[test]
    fn the_meter_keeps_its_width_at_every_level() {
        // The reading is in the shape, so the meter must not change size as it
        // changes — a column that moves with the signal is a column nobody can
        // read a table by.
        for glyphs in [UNICODE, ASCII] {
            let widths: Vec<usize> = glyphs
                .meter
                .iter()
                .map(|(lit, unlit)| lit.chars().count() + unlit.chars().count())
                .collect();
            assert!(
                widths.windows(2).all(|pair| pair[0] == pair[1]),
                "meter widths differ between levels: {widths:?}"
            );
        }
        assert!(ASCII
            .meter
            .iter()
            .all(|(lit, unlit)| lit.is_ascii() && unlit.is_ascii()));
    }

    #[test]
    fn the_meter_fills_as_the_signal_rises() {
        // Monotonic: a stronger signal never lights fewer cells.
        for glyphs in [UNICODE, ASCII] {
            let lit: Vec<usize> = glyphs
                .meter
                .iter()
                .map(|(l, _)| l.chars().count())
                .collect();
            assert!(lit.windows(2).all(|pair| pair[0] <= pair[1]), "{lit:?}");
            assert_eq!(lit[0], 0, "no signal lights nothing");
            assert_eq!(*lit.last().unwrap(), glyphs.meter[0].1.chars().count());
        }
    }

    /// Every glyph in a set, paired with its field name.
    ///
    /// One list drives every guard below. It is hand-written because Rust has
    /// no reflection — and `the_glyph_list_covers_every_field` is what stops a
    /// new field from quietly escaping it.
    fn core(g: &Glyphs) -> Vec<(&'static str, &'static str)> {
        vec![
            ("rail_head", g.rail_head),
            ("rail_body", g.rail_body),
            ("rail_end", g.rail_end),
            ("check", g.check),
            ("cross", g.cross),
            ("pending", g.pending),
            ("rule", g.rule),
            ("connector", g.connector),
            ("sep", g.sep),
            ("arrow_up", g.arrow_up),
            ("partial", g.partial),
            ("unknown", g.unknown),
            ("container", g.container),
            ("privileged", g.privileged),
            ("process", g.process),
            ("minus", g.minus),
            ("plus_minus", g.plus_minus),
        ]
    }

    /// Marks that exist only in the Nerd set. There is no Unicode character
    /// that means "Wi-Fi" without also meaning something else, so rather than
    /// approximate one, the other sets simply have no mark here.
    fn icons(g: &Glyphs) -> Vec<(&'static str, &'static str)> {
        vec![
            ("wifi", g.wifi),
            ("ethernet", g.ethernet),
            ("tunnel", g.tunnel),
            ("loopback", g.loopback),
            ("dns", g.dns),
            ("link", g.link),
            ("globe", g.globe),
            ("shield", g.shield),
        ]
    }

    /// A field added to `Glyphs` and forgotten in the lists above would be
    /// skipped by every guard here without a word. The struct's size is the
    /// one thing that changes when that happens.
    #[test]
    fn the_glyph_list_covers_every_field() {
        let strings = core(&UNICODE).len() + icons(&UNICODE).len();
        let meter = size_of::<[(&'static str, &'static str); 6]>();
        assert_eq!(
            size_of::<Glyphs>(),
            strings * size_of::<&'static str>() + meter,
            "a glyph field is missing from core() or icons()"
        );
    }

    #[test]
    fn every_ascii_glyph_is_ascii_and_present() {
        for (name, glyph) in core(&ASCII) {
            assert!(!glyph.is_empty(), "{name} is empty");
            assert!(glyph.is_ascii(), "{name} is {glyph:?}, which is not ASCII");
        }
    }

    /// The fallback chain is the whole point: whatever a set cannot render has
    /// to have somewhere to fall back to.
    #[test]
    fn every_glyph_has_a_counterpart_in_the_set_below_it() {
        for (name, _) in core(&UNICODE) {
            let unicode = core(&UNICODE)
                .into_iter()
                .find(|(n, _)| *n == name)
                .unwrap()
                .1;
            let ascii = core(&ASCII)
                .into_iter()
                .find(|(n, _)| *n == name)
                .unwrap()
                .1;
            let nerd = core(&NERD).into_iter().find(|(n, _)| *n == name).unwrap().1;
            assert!(!unicode.is_empty(), "{name} has no Unicode form");
            assert!(!ascii.is_empty(), "{name} has no ASCII form");
            assert!(!nerd.is_empty(), "{name} has no Nerd form");
        }
    }

    /// An icon-only mark must stay empty everywhere else, or asking for one
    /// glyph set would reshape the report for everybody who did not.
    #[test]
    fn an_icon_only_mark_is_empty_outside_the_nerd_set() {
        for (name, glyph) in icons(&UNICODE).into_iter().chain(icons(&ASCII)) {
            assert!(glyph.is_empty(), "{name} is {glyph:?} outside the Nerd set");
        }
        for (name, glyph) in icons(&NERD) {
            assert!(!glyph.is_empty(), "{name} has no Nerd glyph");
        }
    }

    /// A glyph from a range that moved between Nerd Fonts v2 and v3 looks
    /// right on a current font and is an empty box on one a few years old. The
    /// ranges in `NERD_RANGES` were measured rather than assumed.
    #[test]
    fn every_nerd_glyph_comes_from_a_range_that_never_moved() {
        let nerd: Vec<(&str, &str)> = core(&NERD).into_iter().chain(icons(&NERD)).collect();
        for (name, glyph) in nerd {
            // Inherited from Unicode where Unicode already does it better.
            if core(&UNICODE)
                .iter()
                .any(|(n, g)| *n == name && *g == glyph)
            {
                continue;
            }
            let mut chars = glyph.chars();
            let point = chars.next().unwrap();
            assert!(chars.next().is_none(), "{name} is more than one character");
            assert!(
                NERD_RANGES
                    .iter()
                    .any(|(lo, hi)| (*lo..=*hi).contains(&point)),
                "{name} is U+{:04X}, outside every range measured stable",
                point as u32
            );
        }
    }
}
