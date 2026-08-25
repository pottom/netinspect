//! The human report.
//!
//! Normative source: `docs/DESIGN.md`. Hue encodes reach and nothing else, so
//! every colour decision in this file goes through `reach::classify` or is a
//! neutral chosen by how much the reader needs the value.
//!
//! Pure: a `Snapshot` in, bytes out. Nothing here touches the system, so every
//! shape of report is reachable from a test.

use crate::model::{
    AddressSource, DnsConfig, Interface, InterfaceKind, InterfaceStatus, Ipv6Scope, PublicAddress,
    Reachability, ReachabilityState, Snapshot, WifiDetail,
};

use super::layout::{
    columns, content_edge, rule, section, visible_width, Line, GUTTER, LABEL_COL, NARROW_BELOW,
    RAIL_BELOW, RAIL_COL, VALUE_COL,
};
use super::reach::{self, Reach};
use super::theme::{Role, Theme};

#[derive(Debug, Clone)]
pub struct Options {
    pub theme: Theme,
    pub width: usize,
    /// Preformatted local time for the header, e.g. `14:22:07 CEST`. The model
    /// carries the machine-readable stamp; the zone abbreviation is not
    /// derivable from it, so it is supplied rather than invented here.
    pub clock: String,
    /// Include inactive and loopback interfaces in full detail.
    pub all: bool,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    /// Restrict the interface section to one interface.
    pub only_interface: Option<String>,
    /// The machine's own IANA time zone, for the comparison against where the
    /// public address says it is.
    pub system_timezone: Option<String>,
    /// Force the content edge, for rendering a block into one of two columns.
    /// `None` derives it from `width`, which is what every caller outside the
    /// renderer wants.
    pub edge: Option<usize>,
}

impl Options {
    fn narrow(&self) -> bool {
        self.width < NARROW_BELOW
    }

    /// Below this the rail costs more columns than it earns.
    fn rail(&self) -> bool {
        self.width >= RAIL_BELOW
    }

    /// A report draws at most two rules, and only when the terminal is wide
    /// enough that they read as structure rather than clutter.
    fn rules(&self) -> bool {
        self.width >= NARROW_BELOW
    }

    /// Where everything right-aligned lands. Follows the terminal rather than
    /// sitting at a fixed 62 and leaving the rest of the screen empty.
    fn edge(&self) -> usize {
        self.edge.unwrap_or_else(|| content_edge(self.width))
    }



    /// Columns available to a value starting at the value column.
    fn value_room(&self) -> usize {
        self.edge().saturating_sub(VALUE_COL - 1)
    }
}

/// Which rail glyph a row carries.
#[derive(Clone, Copy, PartialEq)]
enum Rail {
    /// The interface header — the only rail segment that carries a hue.
    Head(Reach),
    Body,
    End,
    /// Sections and the header, which have no rail at all.
    None,
}

pub fn render(snapshot: &Snapshot, options: &Options) -> String {
    let mut out: Vec<String> = Vec::new();

    header(&mut out, snapshot, options);

    let shown = visible_interfaces(snapshot, options);
    if shown.is_empty() {
        out.push(String::new());
        let mut line = Line::new();
        line.pad_to(LABEL_COL);
        line.push(&options.theme, Role::Faint, "no matching interface");
        out.push(line.finish());
    }

    let mut previous_collapsed = false;
    for (index, iface) in shown.iter().enumerate() {
        let collapsed = !iface.is_active() && !options.all;
        // Consecutive collapsed interfaces read as one list, not as blocks.
        if index == 0 || !(collapsed && previous_collapsed) {
            out.push(String::new());
        }
        interface_block(&mut out, iface, options);
        previous_collapsed = collapsed;
    }

    sections(&mut out, snapshot, options);
    footer(&mut out, snapshot, options);

    let mut text = out.join("\n");
    text.push('\n');
    text
}

// ---------------------------------------------------------------------------
// Header and footer
// ---------------------------------------------------------------------------

fn header(out: &mut Vec<String>, snapshot: &Snapshot, options: &Options) {
    let theme = &options.theme;
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    line.push(theme, Role::Bright, "netinspect");
    line.space(1);
    line.push(theme, Role::Faint, &snapshot.version);

    if options.narrow() {
        line.space(2);
        line.push(theme, Role::Faint, &options.clock);
    } else {
        line.push_right(theme, Role::Faint, &options.clock, options.edge());
    }
    out.push(line.finish());

    if options.rules() {
        out.push(rule(theme, options.edge()));
    }
}

fn footer(out: &mut Vec<String>, snapshot: &Snapshot, options: &Options) {
    let Some(update) = &snapshot.update else {
        return;
    };
    let Some(latest) = update.latest.as_deref().filter(|_| update.available) else {
        return;
    };
    let theme = &options.theme;

    out.push(String::new());
    if options.rules() {
        out.push(rule(theme, options.edge()));
    }

    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    line.push(theme, Role::Faint, theme.glyphs.arrow_up);
    line.space(1);
    line.push(theme, Role::Faint, &format!("{latest} available"));

    // Without colour, the `$` is what marks a line as something to run.
    let command = if theme.monochrome() {
        "$ netinspect self-update".to_owned()
    } else {
        "netinspect self-update".to_owned()
    };
    if options.narrow() {
        out.push(line.finish());
        let mut next = Line::new();
        next.pad_to(LABEL_COL);
        next.push(theme, Role::Action, &command);
        out.push(next.finish());
    } else {
        line.push_right(theme, Role::Action, &command, options.edge());
        out.push(line.finish());
    }
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/// A machine has a dozen or more kernel-internal pseudo-interfaces — idle
/// system tunnels, AWDL, the anpi pair — that macOS itself never shows and that
/// the user has no name for. Listing them buries the three that matter, so an
/// interface that is both inactive and unnamed is hidden unless `--all`.
fn is_worth_showing(iface: &Interface, all: bool) -> bool {
    if all {
        return true;
    }
    if iface.kind == InterfaceKind::Loopback {
        return false;
    }
    iface.is_active() || iface.display_name.is_some()
}

fn visible_interfaces<'a>(snapshot: &'a Snapshot, options: &Options) -> Vec<&'a Interface> {
    snapshot
        .interfaces
        .iter()
        .filter(|iface| match &options.only_interface {
            // An explicitly named interface is always shown, whatever its state.
            Some(name) => &iface.name == name,
            None => is_worth_showing(iface, options.all),
        })
        .collect()
}

/// The interface's own reach, taken from the first address it carries. This is
/// what colours its rail.
fn interface_reach(iface: &Interface) -> Reach {
    if let Some(address) = iface.ipv4.first() {
        return reach::classify(&address.address);
    }
    if let Some(address) = iface.ipv6.first() {
        return reach::classify(&address.address);
    }
    Reach::Lan
}

fn interface_block(out: &mut Vec<String>, iface: &Interface, options: &Options) {
    let theme = &options.theme;
    let active = iface.is_active();

    let mut rows: Vec<Row> = Vec::new();
    if active {
        collect_rows(&mut rows, iface, options);
    }

    // Header
    let mut head = Line::new();
    let head_rail = if active {
        Rail::Head(interface_reach(iface))
    } else {
        Rail::End
    };
    push_rail(&mut head, options, head_rail);

    let name_role = if active { Role::Bright } else { Role::Faint };
    let bsd_role = Role::Faint;
    if let Some(display_name) = header_name(iface) {
        head.push(theme, name_role, &display_name);
        // Colour separates the service name from the device name; without it a
        // separator has to.
        if theme.monochrome() {
            head.push(theme, Role::Faint, &format!(" {} ", theme.glyphs.sep));
        } else {
            head.space(1);
        }
        head.push(theme, bsd_role, &iface.name);
    } else {
        head.push(theme, name_role, &iface.name);
    }

    let status = status_text(iface.status, theme);
    let status_role = status_role(iface.status);
    if options.narrow() {
        head.space(2);
        head.push(theme, status_role, &status);
    } else {
        head.push_right(theme, status_role, &status, options.edge());
    }
    out.push(head.finish());

    // An inactive interface collapses to its header line unless --all.
    for (index, row) in rows.iter().enumerate() {
        let last = index + 1 == rows.len();
        emit_row(out, options, row, if last { Rail::End } else { Rail::Body });
    }
}

/// One label/value row plus its optional annotation and continuation.
struct Row {
    label: String,
    label_role: Role,
    value: Vec<(Role, String)>,
    /// Right-aligned reference material.
    annotation: Option<Vec<(Role, String)>>,
    /// A second line under the value, always `faint`.
    continuation: Option<String>,
}

impl Row {
    fn new(label: impl Into<String>, value: Vec<(Role, String)>) -> Self {
        Row {
            label: label.into(),
            label_role: Role::Dim,
            value,
            annotation: None,
            continuation: None,
        }
    }

    /// The reachability verdict is a state, not a label, so it takes the
    /// state's colour.
    fn with_label_role(mut self, role: Role) -> Self {
        self.label_role = role;
        self
    }

    fn annotate(mut self, text: impl Into<String>) -> Self {
        self.annotation = Some(vec![(Role::Faint, text.into())]);
        self
    }
}

fn collect_rows(rows: &mut Vec<Row>, iface: &Interface, options: &Options) {
    if let Some(wifi) = &iface.wifi {
        if !wifi.is_empty() {
            rows.push(network_row(wifi, options));
        }
    }

    // Absent optional data: omit the row. Never print "unknown".
    if let Some(protocol) = iface.vpn.as_ref().and_then(|v| v.protocol.as_ref()) {
        rows.push(Row::new("protocol", vec![(Role::Body, protocol.clone())]));
    }

    if !options.ipv6_only {
        for (index, address) in iface.ipv4.iter().enumerate() {
            let value = vec![
                (
                    reach::classify(&address.address).role(),
                    address.address.clone(),
                ),
                (Role::Faint, format!("/{}", address.prefix_len)),
            ];
            let mut row = Row::new(if index == 0 { "ipv4" } else { "" }, value);
            if let Some(note) = source_note(address.source, iface) {
                row = row.annotate(note);
            }
            rows.push(row);
        }
    }

    if !options.ipv4_only {
        for (index, address) in iface.ipv6.iter().enumerate() {
            let mut value = vec![(
                reach::classify(&address.address).role(),
                address.address.clone(),
            )];
            // A link-local /64 is universally implied; printing it is noise.
            if address.scope == Ipv6Scope::Global {
                value.push((Role::Faint, format!("/{}", address.prefix_len)));
            }
            rows.push(Row::new(if index == 0 { "ipv6" } else { "" }, value));
        }
    }

    if let Some(vpn) = &iface.vpn {
        if let Some(endpoint) = &vpn.endpoint {
            let mut row = Row::new("endpoint", address_port(endpoint));
            if let Some(seconds) = vpn.last_handshake_seconds {
                row = row.annotate(format!("handshake {} ago", duration(seconds)));
            }
            rows.push(row);
        }
    }

    if let Some(gateway) = &iface.gateway {
        rows.push(Row::new(
            "gateway",
            vec![(reach::classify(gateway).role(), gateway.clone())],
        ));
    }

    // The hardware row is the MAC; the MTU is its annotation. A tunnel has
    // neither to show, so it gets no row rather than a label promising an
    // address it does not have.
    if let Some(mac) = &iface.mac {
        let mut row = Row::new("hardware", vec![(Role::Faint, mac.clone())]);
        if let Some(mtu) = iface.mtu {
            row = row.annotate(format!("mtu {mtu}"));
        }
        rows.push(row);
    }
}

fn network_row(wifi: &WifiDetail, options: &Options) -> Row {
    let theme = &options.theme;
    let value = match &wifi.ssid {
        Some(ssid) => vec![(Role::Bright, ssid.clone())],
        // Say the SSID is unavailable rather than pretending there is none.
        None => vec![(Role::Faint, "<SSID unavailable>".to_owned())],
    };
    let ssid_width: usize = value.iter().map(|(_, t)| t.chars().count()).sum();

    let mut row = Row::new("network", value);

    // Signal strength is a measurement, not a status: the bars are bright and
    // the empty cells are rule. Never green.
    let signal: Vec<(Role, String)> = match wifi.rssi_dbm {
        Some(rssi) => {
            let bars = signal_bars(rssi);
            vec![
                (Role::Bright, theme.glyphs.bar_full.repeat(bars as usize)),
                (
                    Role::Rule,
                    theme.glyphs.bar_empty.repeat(5usize.saturating_sub(bars as usize)),
                ),
                (
                    Role::Faint,
                    format!(" {}{} dBm", theme.glyphs.minus, rssi.abs()),
                ),
            ]
        }
        None => Vec::new(),
    };

    // Everything secondary about the radio: the standard, the negotiated rate,
    // and where the SSID came from if it was not the supported API.
    let mut parts: Vec<String> = Vec::new();
    if let Some(phy) = &wifi.phy_mode {
        parts.push(wifi_generation(phy));
    }
    if let Some(rate) = wifi.rate_mbps {
        parts.push(format!("{rate} Mb/s"));
    }
    if let Some(source) = wifi.ssid_source.and_then(|s| s.annotation()) {
        parts.push(source.to_owned());
    }
    let separator = format!(" {} ", theme.glyphs.sep);
    let secondary = parts.join(&separator);

    // On a wide enough terminal the whole radio fits on one line. It only
    // splits when it has to — the second line is a consequence of the width,
    // not a fixed part of the design.
    let signal_width: usize = signal.iter().map(|(_, t)| t.chars().count()).sum();
    let room = options.value_room().saturating_sub(ssid_width + 2);
    let inline = !secondary.is_empty()
        && !options.narrow()
        && signal_width + separator.chars().count() + secondary.chars().count() <= room;

    row.annotation = match (signal.is_empty(), secondary.is_empty(), inline) {
        (true, true, _) => None,
        (true, false, true) => Some(vec![(Role::Faint, secondary.clone())]),
        (false, _, false) => Some(signal),
        (false, false, true) => {
            let mut all = signal;
            all.push((Role::Faint, format!("{separator}{secondary}")));
            Some(all)
        }
        (false, true, true) => Some(signal),
        (true, false, false) => None,
    };
    if !secondary.is_empty() && !inline {
        row.continuation = Some(secondary);
    }

    row
}

/// `host:port` — the host coloured by reach, the colon faint, the port bright.
/// Splitting the colour at the colon is what makes ports scannable.
///
/// A bare IPv6 literal is full of colons and has no port, so only a bracketed
/// address or a single-colon host is ever split.
fn address_port(endpoint: &str) -> Vec<(Role, String)> {
    fn is_port(text: &str) -> bool {
        !text.is_empty() && text.len() <= 5 && text.chars().all(|c| c.is_ascii_digit())
    }

    if let Some((host, tail)) = endpoint.strip_prefix('[').and_then(|r| r.split_once(']')) {
        if let Some(port) = tail.strip_prefix(':').filter(|p| is_port(p)) {
            return vec![
                (Role::Faint, "[".to_owned()),
                (reach::classify(host).role(), host.to_owned()),
                (Role::Faint, "]:".to_owned()),
                (Role::Bright, port.to_owned()),
            ];
        }
    }

    if endpoint.matches(':').count() == 1 {
        if let Some((host, port)) = endpoint.split_once(':') {
            if !host.is_empty() && is_port(port) {
                return vec![
                    (reach::classify(host).role(), host.to_owned()),
                    (Role::Faint, ":".to_owned()),
                    (Role::Bright, port.to_owned()),
                ];
            }
        }
    }

    vec![(reach::classify(endpoint).role(), endpoint.to_owned())]
}

fn emit_row(out: &mut Vec<String>, options: &Options, row: &Row, rail: Rail) {
    let theme = &options.theme;

    if options.narrow() {
        if !row.label.is_empty() {
            let mut head = Line::new();
            push_rail(&mut head, options, rail);
            head.push(theme, row.label_role, &row.label);
            out.push(head.finish());
        }
        let mut line = Line::new();
        push_rail(&mut line, options, rail);
        line.pad_to(LABEL_COL + 4);
        for (role, text) in &row.value {
            line.push(theme, *role, text);
        }
        out.push(line.finish());

        for extra in [row.annotation.as_deref().map(flatten), row.continuation.clone()]
            .into_iter()
            .flatten()
        {
            let mut line = Line::new();
            push_rail(&mut line, options, rail);
            line.pad_to(LABEL_COL + 4);
            line.push(theme, Role::Faint, &extra);
            out.push(line.finish());
        }
        return;
    }

    let mut line = Line::new();
    push_rail(&mut line, options, rail);
    line.push(theme, row.label_role, &row.label);

    // A label long enough to touch the value column takes the row to itself.
    // The reachability verdict is the case that needs it: "captive portal" is
    // wider than the column, and running it into its own explanation would be
    // unreadable.
    if line.width() + 2 > VALUE_COL {
        out.push(line.finish());
        line = Line::new();
        push_rail(&mut line, options, rail);
    }

    line.pad_to(VALUE_COL);
    for (role, text) in &row.value {
        line.push(theme, *role, text);
    }

    if let Some(annotation) = &row.annotation {
        let width: usize = annotation.iter().map(|(_, t)| t.chars().count()).sum();
        let padding = " ".repeat(width);
        if line.fits_right(&padding, options.edge()) {
            line.pad_to(options.edge() - width + 1);
            for (role, text) in annotation {
                line.push(theme, *role, text);
            }
            out.push(line.finish());
        } else {
            // Never wrap mid-value: the annotation drops to its own line.
            out.push(line.finish());
            let mut extra = Line::new();
            push_rail(&mut extra, options, rail);
            extra.pad_to(VALUE_COL);
            for (role, text) in annotation {
                extra.push(theme, *role, text);
            }
            out.push(extra.finish());
        }
    } else {
        out.push(line.finish());
    }

    if let Some(continuation) = &row.continuation {
        let mut extra = Line::new();
        push_rail(&mut extra, options, rail);
        extra.pad_to(VALUE_COL);
        extra.push(theme, Role::Faint, continuation);
        out.push(extra.finish());
    }
}

fn flatten(fragments: &[(Role, String)]) -> String {
    fragments.iter().map(|(_, t)| t.as_str()).collect()
}

/// The rail is the tool's only decorative glyph, and it is decorative only in
/// shape — its colour is load-bearing.
fn push_rail(line: &mut Line, options: &Options, rail: Rail) {
    let theme = &options.theme;
    if !options.rail() || rail == Rail::None {
        line.pad_to(LABEL_COL);
        return;
    }
    line.pad_to(RAIL_COL);
    match rail {
        Rail::Head(reach) => line.push(theme, reach.role(), theme.glyphs.rail_head),
        Rail::Body => line.push(theme, Role::Rule, theme.glyphs.rail_body),
        Rail::End => line.push(theme, Role::Rule, theme.glyphs.rail_end),
        Rail::None => line,
    };
    line.pad_to(LABEL_COL);
}

/// The name to print before the device name. Prefers the configured service
/// name; for an active interface with none, the kind still says something
/// useful ("VPN utun4"). An inactive unnamed interface gets nothing, because
/// there is nothing to say about it.
fn header_name(iface: &Interface) -> Option<String> {
    if let Some(display_name) = &iface.display_name {
        return Some(display_name.clone());
    }
    if !iface.is_active() {
        return None;
    }
    match iface.kind {
        InterfaceKind::Wifi => Some("Wi-Fi".to_owned()),
        InterfaceKind::Ethernet => Some("Ethernet".to_owned()),
        InterfaceKind::Vpn => Some("VPN".to_owned()),
        InterfaceKind::Bridge => Some("Bridge".to_owned()),
        InterfaceKind::Loopback => Some("Loopback".to_owned()),
        InterfaceKind::Other => None,
    }
}

/// Without colour, a status word needs brackets to read as a state rather than
/// as another value.
fn status_text(status: InterfaceStatus, theme: &Theme) -> String {
    if theme.monochrome() {
        format!("[{}]", status.label())
    } else {
        status.label().to_owned()
    }
}

fn status_role(status: InterfaceStatus) -> Role {
    match status {
        InterfaceStatus::Connected | InterfaceStatus::Up => Role::Ok,
        _ => Role::Faint,
    }
}

/// The DHCP lease expiry is not readable on macOS 15+, so the annotation is
/// just the source. A manually configured address says nothing extra.
fn source_note(source: AddressSource, iface: &Interface) -> Option<String> {
    let _ = iface;
    match source {
        AddressSource::Dhcp => Some("dhcp".to_owned()),
        AddressSource::Linklocal => Some("link-local".to_owned()),
        AddressSource::Manual => None,
    }
}

/// Five cells mapped from RSSI. Presentation, not collection: the platform
/// layer reports dBm and this decides how it looks.
fn signal_bars(rssi_dbm: i32) -> u8 {
    match rssi_dbm {
        r if r >= -50 => 5,
        r if r >= -60 => 4,
        r if r >= -67 => 3,
        r if r >= -75 => 2,
        _ => 1,
    }
}

/// The marketing generation reads better than the standard's name, but only
/// where the mapping is unambiguous. `--json` keeps the raw `802.11xx`.
fn wifi_generation(phy_mode: &str) -> String {
    match phy_mode {
        "802.11ax" => "Wi-Fi 6".to_owned(),
        "802.11ac" => "Wi-Fi 5".to_owned(),
        "802.11n" => "Wi-Fi 4".to_owned(),
        other => other.to_owned(),
    }
}

fn duration(seconds: u64) -> String {
    match seconds {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h {}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d {}h", s / 86400, (s % 86400) / 3600),
    }
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

/// The short sections carry three or four rows each and leave most of a wide
/// terminal empty. Pairing them is what actually spends the extra columns:
/// widening a row that is already short spends nothing.
fn sections(out: &mut Vec<String>, snapshot: &Snapshot, options: &Options) {
    let mut blocks: Vec<Vec<String>> = Vec::new();

    let mut dns = Vec::new();
    dns_section(&mut dns, &snapshot.dns, options);
    blocks.push(dns);

    if let Some(reachability) = &snapshot.reachability {
        let mut ladder = Vec::new();
        reachability_section(&mut ladder, reachability, options);
        blocks.push(ladder);
    }
    if let Some(public) = &snapshot.public {
        let mut block = Vec::new();
        public_section(&mut block, public, options);
        blocks.push(block);
    }

    if options.narrow() {
        out.extend(blocks.into_iter().flatten());
        return;
    }
    out.extend(pack(blocks, options.edge()));
}

/// Place the short sections next to each other while they fit.
///
/// None of them right-aligns anything, so each is exactly as wide as its own
/// content and they can be packed against one another. A fixed half-width
/// column would leave a gap beside the narrow ones and wrap the wide ones.
fn pack(blocks: Vec<Vec<String>>, edge: usize) -> Vec<String> {
    let width = |block: &[String]| block.iter().map(|l| visible_width(l)).max().unwrap_or(0);

    let mut out: Vec<String> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut row_width = 0;

    for block in blocks {
        // Every block opens with the blank line separating it from what came
        // before. Strip it from all of them and emit one per row: left on a
        // block that joins a row it would push that block's title a line above
        // its neighbour's.
        let mut block = block;
        let leading_blank = block.first().is_some_and(|line| line.trim().is_empty());
        if leading_blank {
            block.remove(0);
        }
        let block_width = width(&block);

        if row.is_empty() {
            if leading_blank {
                out.push(String::new());
            }
            row_width = block_width;
            row = block;
        } else if row_width + GUTTER + block_width <= edge {
            row = columns(row, block, row_width + GUTTER + 1);
            row_width += GUTTER + block_width;
        } else {
            out.append(&mut row);
            if leading_blank {
                out.push(String::new());
            }
            row_width = block_width;
            row = block;
        }
    }
    out.append(&mut row);
    out
}

// ---------------------------------------------------------------------------
// Public address
// ---------------------------------------------------------------------------

fn public_section(out: &mut Vec<String>, public: &PublicAddress, options: &Options) {
    out.push(String::new());
    out.push(section(&options.theme, "public address"));

    for (label, address) in [("ipv4", &public.ipv4), ("ipv6", &public.ipv6)] {
        let Some(address) = address else { continue };
        let mut row = Row::new(label, vec![(Role::Public, address.clone())]);
        // Whether the tunnel is actually carrying this traffic is the loudest
        // thing on the page when the answer is no.
        row.annotation = match public.via_vpn {
            Some(true) => Some(vec![(Role::Ok, "via VPN".to_owned())]),
            Some(false) => Some(vec![(Role::Fail, "not routed through VPN".to_owned())]),
            None => None,
        };
        emit_row(out, options, &row, Rail::None);
    }

    if let Some(org) = &public.org {
        let mut row = Row::new("network", vec![(Role::Bright, org.clone())]);
        if let Some(asn) = &public.asn {
            row = row.annotate(asn.clone());
        }
        emit_row(out, options, &row, Rail::None);
    }

    if let Some(place) = place(public) {
        let mut row = Row::new("location", vec![(Role::Body, place)]);
        if let Some(coordinates) = coordinates(public) {
            row = row.annotate(coordinates);
        }
        emit_row(out, options, &row, Rail::None);
    }

    if let Some(timezone) = &public.timezone {
        let mut row = Row::new("timezone", vec![(Role::Body, timezone.clone())]);
        // A mismatch has no reach, no probe outcome and nothing to run, so it
        // gets weight rather than a colour. It is also the normal state with a
        // tunnel up, and exactly the signal people run this tool to see.
        row.annotation = match (public.timezone_matches_system, &options.system_timezone) {
            (Some(true), _) => Some(vec![(Role::Faint, "matches the system clock".to_owned())]),
            (Some(false), Some(ours)) => {
                Some(vec![(Role::Bright, format!("system clock is {ours}"))])
            }
            (Some(false), None) => {
                Some(vec![(Role::Bright, "the system clock differs".to_owned())])
            }
            (None, _) => None,
        };
        emit_row(out, options, &row, Rail::None);
    }
}

/// `Budapest, HU`. The provider reports an ISO country code and this does not
/// carry a table to turn it into a name.
fn place(public: &PublicAddress) -> Option<String> {
    match (&public.city, &public.country) {
        (Some(city), Some(country)) => Some(format!("{city}, {country}")),
        (Some(city), None) => Some(city.clone()),
        (None, Some(country)) => Some(country.clone()),
        (None, None) => None,
    }
}

/// Three decimals is about a hundred metres, which is finer than a city-level
/// lookup can actually resolve. Printing more would imply a precision the
/// number does not have.
fn coordinates(public: &PublicAddress) -> Option<String> {
    let (latitude, longitude) = (public.latitude?, public.longitude?);
    let mut text = format!("{latitude:.3}, {longitude:.3}");
    if let Some(accuracy) = public.accuracy_km {
        text.push_str(&format!(" ±{accuracy} km"));
    }
    Some(text)
}

// ---------------------------------------------------------------------------
// Reachability
// ---------------------------------------------------------------------------

/// One rung: what it is called, whether it was attempted, and how long it took.
struct Rung {
    name: &'static str,
    /// `None` means never attempted — a different fact from failed.
    outcome: Option<bool>,
    ms: Option<u64>,
}

fn rungs(report: &Reachability) -> [Rung; 4] {
    [
        Rung {
            name: "link",
            outcome: report.link.map(|s| s.ok),
            ms: report.link.and_then(|s| s.ms),
        },
        Rung {
            name: "gateway",
            outcome: report.gateway.map(|s| s.ok),
            ms: report.gateway.and_then(|s| s.ms),
        },
        Rung {
            name: "dns",
            outcome: report.dns.map(|s| s.ok),
            ms: report.dns.and_then(|s| s.ms),
        },
        Rung {
            name: "http",
            outcome: report.http.map(|s| s.ok),
            ms: report.http.and_then(|s| s.ms),
        },
    ]
}

fn reachability_section(out: &mut Vec<String>, report: &Reachability, options: &Options) {
    let theme = &options.theme;
    out.push(String::new());
    out.push(section(theme, "reachability"));

    if options.narrow() {
        narrow_ladder(out, report, options);
    } else {
        ladder(out, report, options);
    }

    let (word, role) = verdict(report.state);
    // Without colour a verdict is just another word on the line, so it takes
    // brackets the way an interface status does.
    let word = if theme.monochrome() {
        format!("[{word}]")
    } else {
        word.to_owned()
    };
    emit_row(
        out,
        options,
        &Row::new(word, vec![(Role::Faint, explanation(report).to_owned())])
            .with_label_role(role),
        Rail::None,
    );

    // The login page is the fix, so it has to look like something you can go
    // to rather than another value.
    if let Some(portal) = &report.captive_portal {
        emit_row(
            out,
            options,
            &Row::new("sign in", vec![(Role::Action, portal.login_url.clone())]),
            Rail::None,
        );
    }
}

/// The ladder on one line, timings on the line below, each aligned under the
/// stage it belongs to.
fn ladder(out: &mut Vec<String>, report: &Reachability, options: &Options) {
    let theme = &options.theme;
    let mut line = Line::new();
    line.pad_to(LABEL_COL);
    let mut columns: Vec<(usize, Option<u64>)> = Vec::new();

    for (index, rung) in rungs(report).iter().enumerate() {
        if index > 0 {
            line.push(theme, Role::Rule, &format!(" {} ", theme.glyphs.connector));
        }
        columns.push((line.width() + 1, rung.ms));
        let (role, mark) = mark_for(rung.outcome, theme);
        // A stage that was never attempted is structure, not a result: its
        // name recedes with it.
        let name_role = if rung.outcome.is_some() {
            Role::Bright
        } else {
            Role::Rule
        };
        line.push(theme, name_role, rung.name);
        line.space(1);
        line.push(theme, role, mark);
    }
    out.push(line.finish());

    if columns.iter().any(|(_, ms)| ms.is_some()) {
        let mut timings = Line::new();
        for (column, ms) in columns {
            if let Some(ms) = ms {
                timings.pad_to(column);
                timings.push(theme, Role::Faint, &format!("{ms} ms"));
            }
        }
        out.push(timings.finish());
    }
}

/// Narrow terminals get the rungs wrapped and the timings dropped: which stage
/// broke matters, how many milliseconds it took does not.
fn narrow_ladder(out: &mut Vec<String>, report: &Reachability, options: &Options) {
    let theme = &options.theme;
    let mut line = Line::new();
    line.pad_to(LABEL_COL);
    let mut first = true;

    for rung in rungs(report).iter() {
        let (role, mark) = mark_for(rung.outcome, theme);
        let width = rung.name.chars().count() + 1 + mark.chars().count();
        if !first && line.width() + width + 3 > options.edge() {
            out.push(line.finish());
            line = Line::new();
            line.pad_to(LABEL_COL);
            first = true;
        }
        if !first {
            line.push(theme, Role::Rule, &format!(" {} ", theme.glyphs.connector));
        }
        let name_role = if rung.outcome.is_some() {
            Role::Bright
        } else {
            Role::Rule
        };
        line.push(theme, name_role, rung.name);
        line.space(1);
        line.push(theme, role, mark);
        first = false;
    }
    out.push(line.finish());
}

fn mark_for(outcome: Option<bool>, theme: &Theme) -> (Role, &'static str) {
    match outcome {
        Some(true) => (Role::Ok, theme.glyphs.check),
        Some(false) => (Role::Fail, theme.glyphs.cross),
        // Never attempted. Saying "failed" about something we never tried is
        // the most common way a CLI lies about what it knows.
        None => (Role::Rule, theme.glyphs.pending),
    }
}

/// One word, in the colour of what it says.
fn verdict(state: ReachabilityState) -> (&'static str, Role) {
    match state {
        ReachabilityState::Online => ("online", Role::Ok),
        // The open internet is involved, and the severity is in the word.
        ReachabilityState::CaptivePortal => ("captive portal", Role::Public),
        ReachabilityState::DnsFailure => ("dns failure", Role::Fail),
        ReachabilityState::GatewayUnreachable => ("no gateway", Role::Fail),
        ReachabilityState::LinkDown => ("link down", Role::Fail),
        ReachabilityState::Unknown => ("unknown", Role::Rule),
    }
}

/// Plain language, no jargon. "the network answers, the internet does not"
/// beats "HTTP 302 intercept".
fn explanation(report: &Reachability) -> &'static str {
    match report.state {
        ReachabilityState::Online => {
            if report.http.is_some_and(|s| s.ok) {
                "no captive portal, nothing filtered"
            } else {
                "dns answers, web traffic is filtered"
            }
        }
        ReachabilityState::CaptivePortal => "the network wants you to sign in first",
        ReachabilityState::DnsFailure => "the network answers, the internet does not",
        ReachabilityState::GatewayUnreachable => "this machine cannot reach the router",
        ReachabilityState::LinkDown => "no interface has a usable address",
        ReachabilityState::Unknown => "nothing was determined",
    }
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

fn dns_section(out: &mut Vec<String>, dns: &DnsConfig, options: &Options) {
    let theme = &options.theme;
    out.push(String::new());
    out.push(section(theme, "dns"));

    let mut servers: Vec<(Role, String)> = Vec::new();
    for (index, server) in dns.servers.iter().enumerate() {
        if index > 0 {
            servers.push((Role::Faint, "   ".to_owned()));
        }
        // A resolver on this network and a resolver on the open internet are
        // very different facts, and reach is what says which.
        servers.push((reach::classify(server).role(), server.clone()));
    }
    if !servers.is_empty() {
        emit_row(out, options, &Row::new("servers", servers), Rail::None);
    }

    if !dns.search_domains.is_empty() {
        emit_row(
            out,
            options,
            &Row::new("search", vec![(Role::Body, dns.search_domains.join("  "))]),
            Rail::None,
        );
    }

    let proxy = match &dns.proxy {
        Some(proxy) => vec![(Role::Body, proxy.clone())],
        None => vec![(Role::Faint, "none".to_owned())],
    };
    emit_row(out, options, &Row::new("proxy", proxy), Rail::None);

    // More than one scoped resolver is the normal state with a VPN up, and it
    // explains an answer the global servers would not have given.
    if dns.split_dns_scopes > 1 {
        emit_row(
            out,
            options,
            &Row::new(
                "split-dns",
                vec![(
                    Role::Faint,
                    format!("{} scoped resolvers", dns.split_dns_scopes),
                )],
            ),
            Rail::None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generations_map_only_where_unambiguous() {
        assert_eq!(wifi_generation("802.11ax"), "Wi-Fi 6");
        assert_eq!(wifi_generation("802.11ac"), "Wi-Fi 5");
        // No guessing: 802.11a has no marketing generation.
        assert_eq!(wifi_generation("802.11a"), "802.11a");
    }

    #[test]
    fn rssi_maps_to_bars_at_the_boundaries() {
        assert_eq!(signal_bars(-20), 5);
        assert_eq!(signal_bars(-50), 5);
        assert_eq!(signal_bars(-51), 4);
        assert_eq!(signal_bars(-60), 4);
        assert_eq!(signal_bars(-61), 3);
        assert_eq!(signal_bars(-67), 3);
        assert_eq!(signal_bars(-68), 2);
        assert_eq!(signal_bars(-75), 2);
        assert_eq!(signal_bars(-76), 1);
        assert_eq!(signal_bars(-120), 1);
    }

    #[test]
    fn durations_shorten_as_they_grow() {
        assert_eq!(duration(41), "41s");
        assert_eq!(duration(90), "1m");
        assert_eq!(duration(15113), "4h 11m");
        assert_eq!(duration(200000), "2d 7h");
    }

    #[test]
    fn a_port_is_split_from_its_host() {
        let parts = address_port("51.75.12.9:51820");
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].0, Role::Public);
        assert_eq!(parts[1], (Role::Faint, ":".to_owned()));
        assert_eq!(parts[2], (Role::Bright, "51820".to_owned()));
    }

    #[test]
    fn an_endpoint_without_a_port_is_left_whole() {
        assert_eq!(address_port("51.75.12.9").len(), 1);
        // A bare IPv6 literal is all colons and no port; splitting at the last
        // one would invent a port and mangle the address.
        assert_eq!(address_port("2001:db8::1").len(), 1);
        assert_eq!(address_port("fe80::1").len(), 1);
    }

    #[test]
    fn a_bracketed_ipv6_endpoint_still_splits() {
        let parts = address_port("[2001:db8::1]:51820");
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[1].0, Role::Public);
        assert_eq!(parts[1].1, "2001:db8::1");
        assert_eq!(parts[3], (Role::Bright, "51820".to_owned()));
    }

    #[test]
    fn a_manual_address_carries_no_annotation() {
        // "manual" is what an address is when nothing configured it; saying so
        // on every row is noise.
        let iface = Interface {
            name: "en0".to_owned(),
            display_name: None,
            kind: InterfaceKind::Ethernet,
            status: InterfaceStatus::Connected,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            gateway: None,
            mac: None,
            mtu: None,
            dhcp: None,
            wifi: None,
            vpn: None,
            is_default_route: false,
        };
        assert_eq!(source_note(AddressSource::Manual, &iface), None);
        assert_eq!(source_note(AddressSource::Dhcp, &iface).as_deref(), Some("dhcp"));
    }
}
