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
/// Annotations and interface status right-align here; a full line is this wide.
pub const RIGHT_EDGE: usize = 62;
/// Below this terminal width the layout stacks instead of aligning.
pub const NARROW_BELOW: usize = 66;
/// Below this the rail is dropped too.
pub const RAIL_BELOW: usize = 40;

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
    pub fn push_right(&mut self, theme: &Theme, role: Role, text: &str, column: usize) -> &mut Self {
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
pub fn rule(theme: &Theme) -> String {
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    line.push(
        theme,
        Role::Rule,
        &theme.glyphs.rule.repeat(RIGHT_EDGE - MARGIN),
    );
    line.finish()
}

/// A section title: uppercase, in `dim`, with no rule under it.
pub fn section(theme: &Theme, title: &str) -> String {
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
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
    fn right_alignment_lands_on_the_content_edge() {
        let theme = Theme::plain();
        let mut line = Line::new();
        line.pad_to(RAIL_COL);
        line.push(&theme, Role::Bright, "Wi-Fi");
        line.push_right(&theme, Role::Ok, "connected", RIGHT_EDGE);
        assert_eq!(line.width(), RIGHT_EDGE);
        assert!(line.finish().ends_with("connected"));
    }

    #[test]
    fn fits_right_reserves_a_gap() {
        let theme = Theme::plain();
        let mut line = Line::new();
        line.pad_to(VALUE_COL);
        line.push(&theme, Role::Lan, "192.168.1.24");
        assert!(line.fits_right("dhcp", RIGHT_EDGE));
        // Something that would touch the value has to go on its own row.
        assert!(!line.fits_right(&"x".repeat(40), RIGHT_EDGE));
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
        assert_eq!(rule(&theme).chars().count(), RIGHT_EDGE);
    }

    #[test]
    fn section_titles_are_uppercase_and_unruled() {
        let theme = Theme::plain();
        assert_eq!(section(&theme, "public address"), "  PUBLIC ADDRESS");
        assert_eq!(section(&theme, "dns"), "  DNS");
    }
}
