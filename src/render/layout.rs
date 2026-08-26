//! Column arithmetic for the human report.
//!
//! Normative source: `docs/DESIGN.md` §4.
//!
//! Fragments carry a role rather than a colour, and the line tracks its own
//! visible width so padding stays correct whether or not escape sequences were
//! emitted. Getting this wrong is how a report that looks fine uncoloured falls
//! apart on a real terminal.

use super::theme::{Role, Theme};

/// Content starts at column 3; columns here are 1-based.
pub const MARGIN: usize = 2;
/// The left rail sits in the margin's last column.
pub const RAIL_COL: usize = 3;
/// The label column. Sections indent to the same place without a rail.
pub const LABEL_COL: usize = 5;
/// Labels are padded to this width, putting values at column 17.
pub const LABEL_WIDTH: usize = 12;
pub const VALUE_COL: usize = LABEL_COL + LABEL_WIDTH;
/// The narrowest content the report is designed for, and the width every
/// column position is derived from.
pub const CONTENT_MIN: usize = 62;
/// The widest it grows to. Past this an annotation right-aligned against the
/// edge is too far from the label it belongs to for the eye to pair them, and
/// the extra room stops being worth anything.
pub const CONTENT_MAX: usize = 96;

/// Where annotations and interface status right-align, given the terminal.
///
/// The report used to be a fixed 62 columns, which left a wide terminal mostly
/// empty and forced rows to stack that had room to sit on one line. It now
/// follows the terminal between the two bounds above, keeping a two-column
/// gutter on the right to match the margin on the left. At 80 columns the edge
/// lands on 78 — exactly where a typical radio row stops needing a second
/// line.
pub fn content_edge(terminal_width: usize) -> usize {
    terminal_width
        .saturating_sub(MARGIN)
        .clamp(CONTENT_MIN, CONTENT_MAX)
}
/// Below this terminal width the layout stacks instead of aligning.
pub const NARROW_BELOW: usize = 66;
/// Below this the rail is dropped too.
pub const RAIL_BELOW: usize = 40;

/// Columns between two side-by-side blocks, on top of the right block's own
/// two-column margin.
pub const GUTTER: usize = 2;
/// Below this the sections stay stacked: two columns narrower than this make
/// every second row wrap, which costs more lines than the pairing saves.
pub const PAIR_SECTIONS_FROM: usize = 92;

/// Visible columns in a rendered line, ignoring ANSI escape sequences.
///
/// `Line` tracks this as it builds, but a finished block has to be measured
/// again to be placed beside another one.
pub fn visible_width(line: &str) -> usize {
    let mut width = 0;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI ... m — skip to the terminator.
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        width += 1;
    }
    width
}

/// Place two rendered blocks side by side, the right one starting at `column`.
///
/// The right block's lines are appended **verbatim**, leading spaces included:
/// those spaces are the block's own column arithmetic, and trimming them would
/// silently unalign everything inside it.
pub fn columns(left: Vec<String>, right: Vec<String>, column: usize) -> Vec<String> {
    let height = left.len().max(right.len());
    (0..height)
        .map(|index| {
            let mut line = left.get(index).cloned().unwrap_or_default();
            let Some(other) = right.get(index).filter(|text| !text.trim().is_empty()) else {
                // Nothing to the right: do not leave trailing spaces behind.
                return line.trim_end().to_owned();
            };
            for _ in visible_width(&line)..column - 1 {
                line.push(' ');
            }
            line.push_str(other);
            line
        })
        .collect()
}

/// A single output line under construction.
pub struct Line {
    buf: String,
    /// Visible columns written so far, ignoring escape sequences.
    width: usize,
}

impl Line {
    pub fn new() -> Self {
        Line {
            buf: String::new(),
            width: 0,
        }
    }

    pub fn width(&self) -> usize {
        self.width
    }

    /// Pad with spaces until the next character would land on `column`.
    /// Never truncates: a value that has already overrun its column keeps its
    /// content and pushes the rest of the line right.
    pub fn pad_to(&mut self, column: usize) -> &mut Self {
        while self.width + 1 < column {
            self.buf.push(' ');
            self.width += 1;
        }
        self
    }

    pub fn push(&mut self, theme: &Theme, role: Role, text: &str) -> &mut Self {
        if text.is_empty() {
            return self;
        }
        self.buf.push_str(&theme.paint(role, text));
        self.width += text.chars().count();
        self
    }

    pub fn space(&mut self, count: usize) -> &mut Self {
        for _ in 0..count {
            self.buf.push(' ');
            self.width += 1;
        }
        self
    }

    /// Right-align `text` so that it ends at `column`, leaving at least one
    /// space after whatever is already on the line.
    pub fn push_right(
        &mut self,
        theme: &Theme,
        role: Role,
        text: &str,
        column: usize,
    ) -> &mut Self {
        let len = text.chars().count();
        self.pad_to(column.saturating_sub(len) + 1);
        self.push(theme, role, text)
    }

    /// Whether `text` would still fit when right-aligned to `column`, keeping a
    /// two-space gap after the existing content.
    pub fn fits_right(&self, text: &str, column: usize) -> bool {
        let len = text.chars().count();
        column >= len && column - len >= self.width + 2
    }

    pub fn finish(self) -> String {
        self.buf
    }
}

impl Default for Line {
    fn default() -> Self {
        Line::new()
    }
}

/// A horizontal rule spanning the content width. A report draws at most two:
/// the header underline and the footer, and only in a terminal wide enough that
/// they read as structure rather than clutter.
pub fn rule(theme: &Theme, edge: usize) -> String {
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    line.push(
        theme,
        Role::Rule,
        &theme.glyphs.rule.repeat(edge.saturating_sub(MARGIN)),
    );
    line.finish()
}

/// A section title: uppercase, in `dim`, with no rule under it.
pub fn section(theme: &Theme, title: &str) -> String {
    marked_section(theme, "", title)
}

/// A section title with a leading mark.
///
/// The mark is empty in every glyph set but Nerd, and an empty mark takes no
/// space at all — so the report is byte-for-byte what it was for everyone who
/// has not asked for icons.
pub fn marked_section(theme: &Theme, icon: &str, title: &str) -> String {
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    if !icon.is_empty() {
        line.push(theme, Role::Dim, icon);
        line.space(1);
    }
    line.push(theme, Role::Dim, &title.to_uppercase());
    line.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::theme::{ColorMode, Palette, UNICODE};

    fn coloured() -> Theme {
        Theme {
            color: ColorMode::TrueColor,
            palette: Palette::Dark,
            glyphs: UNICODE,
        }
    }

    #[test]
    fn padding_counts_visible_columns_not_bytes() {
        let theme = coloured();
        let mut line = Line::new();
        line.pad_to(LABEL_COL);
        line.push(&theme, Role::Dim, "ipv4").pad_to(VALUE_COL);
        line.push(&theme, Role::Lan, "10.0.0.1");
        // Escape sequences must not shift the value column.
        assert_eq!(line.width(), VALUE_COL - 1 + "10.0.0.1".chars().count());
    }

    #[test]
    fn the_content_follows_the_terminal_between_its_bounds() {
        // A terminal exactly as wide as the design's minimum keeps it.
        assert_eq!(content_edge(64), CONTENT_MIN);
        // 80 columns is where a typical radio row stops needing a second line.
        assert_eq!(content_edge(80), 78);
        assert_eq!(content_edge(100), 96);
        // Past the maximum the extra room buys nothing, so it is not taken.
        assert_eq!(content_edge(200), CONTENT_MAX);
        // Narrower than the design: the stacked layout takes over, and the
        // arithmetic must not underflow on the way there.
        assert_eq!(content_edge(20), CONTENT_MIN);
        assert_eq!(content_edge(0), CONTENT_MIN);
    }

    #[test]
    fn right_alignment_lands_on_the_content_edge() {
        let theme = Theme::plain();
        let mut line = Line::new();
        line.pad_to(RAIL_COL);
        line.push(&theme, Role::Bright, "Wi-Fi");
        line.push_right(&theme, Role::Ok, "connected", CONTENT_MIN);
        assert_eq!(line.width(), CONTENT_MIN);
        assert!(line.finish().ends_with("connected"));
    }

    #[test]
    fn fits_right_reserves_a_gap() {
        let theme = Theme::plain();
        let mut line = Line::new();
        line.pad_to(VALUE_COL);
        line.push(&theme, Role::Lan, "192.168.1.24");
        assert!(line.fits_right("dhcp", CONTENT_MIN));
        // Something that would touch the value has to go on its own row.
        assert!(!line.fits_right(&"x".repeat(40), CONTENT_MIN));
    }

    #[test]
    fn an_overlong_value_is_never_truncated() {
        let theme = Theme::plain();
        let mut line = Line::new();
        line.push(&theme, Role::Body, "0123456789");
        line.pad_to(4); // already past it
        line.push(&theme, Role::Body, "x");
        assert_eq!(line.finish(), "0123456789x");
    }

    #[test]
    fn rules_span_the_content_width() {
        let theme = Theme::plain();
        assert_eq!(rule(&theme, CONTENT_MIN).chars().count(), CONTENT_MIN);
        assert_eq!(rule(&theme, CONTENT_MAX).chars().count(), CONTENT_MAX);
    }

    #[test]
    fn escape_sequences_do_not_count_as_columns() {
        assert_eq!(visible_width("  DNS"), 5);
        assert_eq!(visible_width("\x1b[38;2;1;2;3mDNS\x1b[0m"), 3);
        assert_eq!(visible_width("\x1b[1m\x1b[2mab\x1b[0m"), 2);
    }

    #[test]
    fn blocks_sit_side_by_side_without_trailing_space() {
        let composed = columns(
            vec!["  DNS".to_owned(), "    servers".to_owned()],
            vec!["  REACHABILITY".to_owned()],
            19,
        );
        assert_eq!(composed[0], "  DNS               REACHABILITY");
        // The left block outlives the right one; that row must not be padded.
        assert_eq!(composed[1], "    servers");
    }

    #[test]
    fn the_right_blocks_own_indentation_survives() {
        // Its leading spaces are its column arithmetic — the reachability
        // timings are aligned under their stage names by nothing else.
        let composed = columns(
            vec!["  A".to_owned(), "  B".to_owned()],
            vec!["  link ok".to_owned(), "       12 ms".to_owned()],
            11,
        );
        assert_eq!(composed[0], "  A         link ok");
        assert_eq!(composed[1], "  B              12 ms");
    }

    #[test]
    fn a_taller_right_block_still_lands_in_its_column() {
        let composed = columns(
            vec!["  A".to_owned()],
            vec!["  X".to_owned(), "  Y".to_owned()],
            11,
        );
        assert_eq!(composed[0], "  A         X");
        assert_eq!(composed[1], "            Y");
    }

    #[test]
    fn section_titles_are_uppercase_and_unruled() {
        let theme = Theme::plain();
        assert_eq!(section(&theme, "public address"), "  PUBLIC ADDRESS");
        assert_eq!(section(&theme, "dns"), "  DNS");
    }
}
