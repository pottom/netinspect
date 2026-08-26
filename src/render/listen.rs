//! The `listen` table.
//!
//! Grouped by exposure, most exposed first: the dangerous group must never be
//! below the fold. A socket whose owner could not be determined still gets its
//! row, with an em dash where the name would be — omitting it because we could
//! not name it would make this actively misleading as a security check.

use crate::model::{Exposure, FirewallMode, FirewallState, SocketEntry, SocketTable};

use super::layout::{rule, Line, MARGIN, RAIL_COL};
use super::reach::Reach;
use super::theme::{Role, Theme};

/// Rows sit one step past the rail, as in `routes`.
const ROW_COL: usize = 6;
const PROTO_WIDTH: usize = 7;
const GAP: usize = 2;
/// How much of a wide terminal's surplus any one column may absorb.
const SPREAD: usize = 8;

#[derive(Debug, Clone)]
pub struct Options {
    pub theme: Theme,
    pub edge: usize,
    /// Who is running this, so a socket owned by somebody else can say so.
    /// `None` annotates every owner.
    pub current_uid: Option<u32>,
    /// Name the well-known ports. Off by default: it adds noise.
    pub resolve: bool,
}

/// Most exposed first.
const GROUPS: [(Exposure, Reach); 3] = [
    (Exposure::Wildcard, Reach::Public),
    (Exposure::Interface, Reach::Lan),
    (Exposure::Loopback, Reach::Local),
];

struct Widths {
    address: usize,
    owner: usize,
    detail: usize,
    pid: usize,
}

/// Column widths, measured from the data and then given room to breathe.
///
/// Measuring alone leaves this table packed into the left half of a wide
/// terminal while `routes` — whose IPv6 destinations are long enough to push
/// its own columns apart — fills it. The difference is in the data, not in the
/// design, so the surplus is spread across the columns rather than left as one
/// dead margin on the right. Capped, because a column pushed halfway across a
/// very wide terminal stops being a column and becomes two lists.
fn widths(sockets: &[SocketEntry], theme: &Theme, options: &Options) -> Widths {
    let longest = |f: &dyn Fn(&SocketEntry) -> usize, header: &str| {
        sockets.iter().map(f).max().unwrap_or(0).max(header.len())
    };

    let mut address = longest(
        &|socket| {
            let mut width = address_text(socket).chars().count();
            // The service name sits in the address column, so it has to be
            // measured with it or it runs into the owner.
            if options.resolve {
                if let Some(name) = service_name(socket.port, socket.protocol) {
                    width += 1 + name.chars().count();
                }
            }
            width
        },
        "address",
    ) + GAP;
    let mut owner = longest(&|socket| owner_text(socket, theme).chars().count(), "owner") + GAP;

    // A column nothing fills is a column that should not be there.
    let detail_content = longest(&|socket| detail_text(socket, options).chars().count(), "");
    let mut detail = if detail_content == 0 {
        0
    } else {
        detail_content + GAP
    };

    let pid = longest(
        &|socket| match &socket.process {
            Some(process) => process.pid.to_string().chars().count(),
            None => theme.glyphs.unknown.chars().count(),
        },
        "pid",
    );

    // What is left once the row's fixed parts are accounted for.
    let fixed = ROW_COL - 1 + PROTO_WIDTH + pid;
    let available = options.edge.saturating_sub(fixed);
    let natural = address + owner + detail;
    if natural < available {
        // Evenly, so no single column swallows the terminal.
        let each = (available - natural) / 3;
        address += each.min(SPREAD);
        owner += each.min(SPREAD);
        if detail > 0 {
            detail += each.min(SPREAD);
        }
    }

    Widths {
        address,
        owner,
        detail,
        pid,
    }
}

/// What kind of owner holds this socket.
///
/// Every row gets a mark, not only the container rows. One marked row among
/// unmarked ones reads as an exception rather than as a column, and the names
/// stop lining up — which is the whole reason the column exists.
fn owner_mark(socket: &SocketEntry, theme: &Theme) -> &'static str {
    match (&socket.container, &socket.process) {
        (Some(_), _) => theme.glyphs.container,
        // Root holding a port is the row worth finding in this table, so it
        // gets a shape of its own rather than sharing one with every daemon.
        (None, Some(process)) if process.uid == 0 => theme.glyphs.privileged,
        (None, Some(_)) => theme.glyphs.process,
        // No mark. The name is already an em dash, and a second symbol for the
        // same absence says nothing the first did not. The space is still
        // reserved, so the names stay in one column.
        (None, None) => "",
    }
}

/// The mark and the space after it. Every row spends this, marked or not.
fn mark_width(theme: &Theme) -> usize {
    theme.glyphs.container.chars().count() + 1
}

/// What goes in the owner column: the container's name when we have it, and
/// the process holding the socket when we do not.
///
/// A container's name is the answer to the question the reader is asking. The
/// forwarder process — `OrbStack Helper` and its like — is a helper nobody
/// started on purpose, and naming it where the owner belongs is how this table
/// ends up explaining nothing.
fn owner_name(socket: &SocketEntry, theme: &Theme) -> String {
    match (&socket.container, &socket.process) {
        (Some(container), process) => match (&container.name, process) {
            (Some(name), _) => name.clone(),
            // The runtime could not be asked. Saying which helper holds the
            // socket is then the most that is true.
            (None, Some(process)) => process.name.clone(),
            (None, None) => theme.glyphs.unknown.to_owned(),
        },
        (None, Some(process)) => process.name.clone(),
        (None, None) => theme.glyphs.unknown.to_owned(),
    }
}

/// The owner column as it will be measured: mark, a space, then the name.
fn owner_text(socket: &SocketEntry, theme: &Theme) -> String {
    format!(
        "{}{}",
        " ".repeat(mark_width(theme)),
        owner_name(socket, theme)
    )
}

/// The faint column after the owner: what the owner *is*.
fn detail_text(socket: &SocketEntry, options: &Options) -> String {
    if let Some(container) = &socket.container {
        return match &container.image {
            Some(image) => image.clone(),
            // Unnamed: say which runtime recognised it, so the marker is not a
            // claim without a source.
            None => format!("{} container", container.runtime),
        };
    }
    // Only when it is somebody else's.
    match &socket.process {
        Some(process) if options.current_uid.is_none_or(|uid| uid != process.uid) => process
            .user
            .clone()
            .unwrap_or_else(|| process.uid.to_string()),
        _ => String::new(),
    }
}

/// `192.168.1.24:8384`, or `[::1]:631` — an IPv6 address needs its brackets or
/// the port is just another group.
fn address_text(socket: &SocketEntry) -> String {
    if socket.address.contains(':') {
        format!("[{}]:{}", socket.address, socket.port)
    } else {
        format!("{}:{}", socket.address, socket.port)
    }
}

pub fn render(table: &SocketTable, firewall: FirewallState, options: &Options) -> String {
    let theme = &options.theme;
    let mut out: Vec<String> = Vec::new();

    out.push(heading(theme, "listening", options.edge));
    let widths = widths(&table.sockets, theme, options);

    for (exposure, reach) in GROUPS {
        let group: Vec<&SocketEntry> = table
            .sockets
            .iter()
            .filter(|socket| socket.exposure == exposure)
            .collect();
        // An empty group is omitted entirely, header and all.
        if group.is_empty() {
            continue;
        }

        out.push(String::new());
        out.push(group_header(theme, reach, group.len(), options.edge));
        // A blank line under the group title, as in `routes`: the column
        // header is a different kind of row from the one above it, and running
        // them together is what made this table read as dense.
        out.push(String::new());
        out.push(column_header(theme, &widths));
        for socket in group {
            out.push(row(theme, socket, &widths, options));
        }
    }

    if table.sockets.is_empty() {
        out.push(String::new());
        let mut line = Line::new();
        line.pad_to(RAIL_COL);
        line.push(theme, Role::Faint, "nothing is listening");
        out.push(line.finish());
    }

    out.push(String::new());
    out.push(rule(theme, options.edge));
    footer(&mut out, table, firewall, options);

    let mut text = out.join("\n");
    text.push('\n');
    text
}

fn heading(theme: &Theme, title: &str, edge: usize) -> String {
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    line.push(theme, Role::Dim, title);
    line.space(1);
    let used = line.width() - MARGIN;
    line.push(
        theme,
        Role::Rule,
        &theme.glyphs.rule.repeat(edge.saturating_sub(MARGIN + used)),
    );
    line.finish()
}

/// The rail carries the group's reach colour; the count is reference material.
fn group_header(theme: &Theme, reach: Reach, count: usize, edge: usize) -> String {
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    line.push(theme, reach.role(), theme.glyphs.rail_head);
    line.space(2);
    line.push(theme, Role::Bright, reach.group_title());

    let plural = if count == 1 { "socket" } else { "sockets" };
    line.push_right(theme, Role::Faint, &format!("{count} {plural}"), edge);
    line.finish()
}

fn column_header(theme: &Theme, widths: &Widths) -> String {
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    line.push(theme, Role::Rule, theme.glyphs.rail_body);
    line.pad_to(ROW_COL);
    line.push(theme, Role::Dim, "proto");
    line.pad_to(ROW_COL + PROTO_WIDTH);
    line.push(theme, Role::Dim, "address");
    line.pad_to(ROW_COL + PROTO_WIDTH + widths.address);
    line.push(theme, Role::Dim, "owner");
    line.push_right(theme, Role::Dim, "pid", pid_end(widths));
    line.finish()
}

/// The pid column ends the row, and every row ends in the same place.
fn pid_end(widths: &Widths) -> usize {
    ROW_COL + PROTO_WIDTH + widths.address + widths.owner + widths.detail + widths.pid - 1
}

fn row(theme: &Theme, socket: &SocketEntry, widths: &Widths, options: &Options) -> String {
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    line.push(theme, Role::Rule, theme.glyphs.rail_body);

    line.pad_to(ROW_COL);
    line.push(theme, Role::Body, protocol(socket));

    // The host is coloured by reach and the port is bright. Splitting the
    // colour at the colon is what makes a port scannable in a long list.
    line.pad_to(ROW_COL + PROTO_WIDTH);
    let role = exposure_role(socket.exposure);
    if socket.address.contains(':') {
        line.push(theme, role, &format!("[{}]", socket.address));
    } else {
        line.push(theme, role, &socket.address);
    }
    line.push(theme, Role::Faint, ":");
    line.push(theme, Role::Bright, &socket.port.to_string());

    if options.resolve {
        if let Some(name) = service_name(socket.port, socket.protocol) {
            line.push(theme, Role::Faint, &format!(" {name}"));
        }
    }

    line.pad_to(ROW_COL + PROTO_WIDTH + widths.address);
    owner(&mut line, theme, socket);

    let detail = detail_text(socket, options);
    if !detail.is_empty() {
        line.pad_to(ROW_COL + PROTO_WIDTH + widths.address + widths.owner);
        line.push(theme, Role::Faint, &detail);
    }

    match &socket.process {
        Some(process) => {
            line.push_right(
                theme,
                Role::Faint,
                &process.pid.to_string(),
                pid_end(widths),
            );
        }
        None => {
            line.push_right(theme, Role::Faint, theme.glyphs.unknown, pid_end(widths));
        }
    }
    line.finish()
}

/// The owner column, written out with its parts coloured separately.
///
/// The mark carries no hue of its own: the shape says what kind of owner this
/// is, and the row already says in colour how far away the port can be reached
/// from. Giving the mark a hue too would be the same fact told twice, in a
/// column where a second signal only competes with the first.
fn owner(line: &mut Line, theme: &Theme, socket: &SocketEntry) {
    let mark = owner_mark(socket, theme);
    if mark.is_empty() {
        line.space(mark_width(theme));
    } else {
        line.push(theme, Role::Faint, mark);
        line.space(mark_width(theme) - mark.chars().count());
    }
    let name = owner_name(socket, theme);
    // A named container is the answer to the question; an unnamed owner is the
    // absence of one, and they must not look alike.
    let role = match (&socket.container, &socket.process) {
        (Some(container), _) if container.name.is_some() => Role::Bright,
        (_, Some(_)) => Role::Body,
        (_, None) => Role::Faint,
    };
    line.push(theme, role, &name);
}

fn protocol(socket: &SocketEntry) -> &'static str {
    match socket.protocol {
        crate::model::Protocol::Tcp => "tcp",
        crate::model::Protocol::Udp => "udp",
    }
}

fn exposure_role(exposure: Exposure) -> Role {
    match exposure {
        Exposure::Wildcard => Role::Public,
        Exposure::Interface => Role::Lan,
        Exposure::Loopback => Role::Local,
    }
}

fn footer(out: &mut Vec<String>, table: &SocketTable, firewall: FirewallState, options: &Options) {
    let theme = &options.theme;

    // Never omit a socket for want of a name — say how many there were, and
    // what would fix it.
    if table.summary.unattributed > 0 {
        let mut line = Line::new();
        line.pad_to(RAIL_COL);
        let plural = if table.summary.unattributed == 1 {
            "socket"
        } else {
            "sockets"
        };
        line.push(
            theme,
            Role::Faint,
            &format!(
                "{} {plural} owned by other users {} ",
                table.summary.unattributed, theme.glyphs.sep
            ),
        );
        // It is the fix, so it has to look like something you can run.
        let command = if theme.monochrome() {
            "$ sudo netinspect listen"
        } else {
            "sudo netinspect listen"
        };
        line.push(theme, Role::Action, command);
        out.push(line.finish());
    }

    // Wording that hedges, deliberately. The macOS application firewall filters
    // by application rather than by port, so this cannot honestly claim a given
    // port is closed.
    let (state, role, explanation) = match firewall.state {
        FirewallMode::Off => (
            "off",
            Role::Public,
            Some(format!(
                "{} the {} exposed {} accept connections",
                theme.glyphs.unknown,
                table.summary.wildcard,
                if table.summary.wildcard == 1 {
                    "port"
                } else {
                    "ports"
                }
            )),
        ),
        FirewallMode::On => (
            "on",
            Role::Ok,
            Some(format!(
                "{} exposed ports may still be filtered per app",
                theme.glyphs.unknown
            )),
        ),
        FirewallMode::BlockAll => ("blocking all incoming", Role::Ok, None),
        // Silence beats a guess here, and the row goes entirely.
        FirewallMode::Unknown => return,
    };

    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    if !theme.glyphs.shield.is_empty() {
        line.push(theme, Role::Dim, theme.glyphs.shield);
        line.space(1);
    }
    line.push(theme, Role::Dim, "application firewall");
    line.space(2);
    line.push(theme, role, state);
    if let Some(explanation) = explanation {
        line.space(2);
        line.push(theme, Role::Faint, &explanation);
    }
    out.push(line.finish());
}

/// Well-known ports, for `--resolve`.
///
/// A compiled-in table rather than a lookup: `/etc/services` is a file read in
/// the middle of a pure renderer, and the names people actually recognise are
/// a short list. Anything not here is left unannotated rather than guessed at.
pub fn service_name(port: u16, protocol: crate::model::Protocol) -> Option<&'static str> {
    use crate::model::Protocol::{Tcp, Udp};
    let name = match (port, protocol) {
        (22, Tcp) => "ssh",
        (25, Tcp) => "smtp",
        (53, _) => "domain",
        (67 | 68, Udp) => "dhcp",
        (80, Tcp) => "http",
        (88, _) => "kerberos",
        (123, Udp) => "ntp",
        (137..=139, _) => "netbios",
        (143, Tcp) => "imap",
        (389, Tcp) => "ldap",
        (443, Tcp) => "https",
        (445, Tcp) => "smb",
        (500, Udp) => "isakmp",
        (548, Tcp) => "afp",
        (587, Tcp) => "submission",
        (631, _) => "ipp",
        (993, Tcp) => "imaps",
        (1433, Tcp) => "mssql",
        (1521, Tcp) => "oracle",
        (3000, Tcp) => "dev-server",
        (3306, Tcp) => "mysql",
        (3389, Tcp) => "rdp",
        (5000, Tcp) => "upnp",
        (5060 | 5061, _) => "sip",
        (5353, Udp) => "mdns",
        (5432, Tcp) => "postgresql",
        (5900, Tcp) => "vnc",
        (6379, Tcp) => "redis",
        (7000, Tcp) => "airplay",
        (8080, Tcp) => "http-alt",
        (8443, Tcp) => "https-alt",
        (9000, Tcp) => "cslistener",
        (11211, Tcp) => "memcached",
        (27017, Tcp) => "mongodb",
        _ => return None,
    };
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Family, ProcessInfo, Protocol, SocketSummary};

    fn socket(
        address: &str,
        port: u16,
        exposure: Exposure,
        process: Option<(&str, i32, u32)>,
    ) -> SocketEntry {
        SocketEntry {
            container: None,
            protocol: Protocol::Tcp,
            family: if address.contains(':') {
                Family::Inet6
            } else {
                Family::Inet
            },
            address: address.to_owned(),
            port,
            state: "listen".to_owned(),
            exposure,
            process: process.map(|(name, pid, uid)| ProcessInfo {
                name: name.to_owned(),
                pid,
                uid,
                user: Some(if uid == 0 {
                    "root".to_owned()
                } else {
                    "maya".to_owned()
                }),
                path: None,
            }),
        }
    }

    fn table(sockets: Vec<SocketEntry>) -> SocketTable {
        let count = |exposure: Exposure| sockets.iter().filter(|s| s.exposure == exposure).count();
        let summary = SocketSummary {
            total: sockets.len(),
            wildcard: count(Exposure::Wildcard),
            loopback: count(Exposure::Loopback),
            interface: count(Exposure::Interface),
            unattributed: sockets.iter().filter(|s| s.process.is_none()).count(),
        };
        SocketTable { sockets, summary }
    }

    fn options() -> Options {
        Options {
            theme: Theme::plain(),
            edge: 78,
            current_uid: Some(501),
            resolve: false,
        }
    }

    fn firewall(state: FirewallMode) -> FirewallState {
        FirewallState {
            state,
            block_all_incoming: state == FirewallMode::BlockAll,
        }
    }

    #[test]
    fn the_dangerous_group_comes_first() {
        let rendered = render(
            &table(vec![
                socket(
                    "127.0.0.1",
                    6379,
                    Exposure::Loopback,
                    Some(("redis", 4021, 501)),
                ),
                socket(
                    "0.0.0.0",
                    5432,
                    Exposure::Wildcard,
                    Some(("postgres", 1284, 501)),
                ),
                socket(
                    "192.168.1.24",
                    8384,
                    Exposure::Interface,
                    Some(("syncthing", 2077, 501)),
                ),
            ]),
            firewall(FirewallMode::Unknown),
            &options(),
        );
        let order: Vec<&str> = rendered
            .lines()
            .filter(|line| {
                line.contains("reachable")
                    || line.contains("bound to")
                    || line.contains("machine only")
            })
            .collect();
        assert_eq!(order.len(), 3);
        assert!(order[0].contains("reachable from the network"));
        assert!(order[1].contains("bound to one interface"));
        assert!(order[2].contains("this machine only"));
    }

    #[test]
    fn an_empty_group_is_omitted_header_and_all() {
        let rendered = render(
            &table(vec![socket(
                "127.0.0.1",
                6379,
                Exposure::Loopback,
                Some(("redis", 4021, 501)),
            )]),
            firewall(FirewallMode::Unknown),
            &options(),
        );
        assert!(
            !rendered.contains("reachable from the network"),
            "{rendered}"
        );
        assert!(rendered.contains("this machine only"), "{rendered}");
        assert!(
            rendered.contains("1 socket\n") || rendered.contains("1 socket "),
            "{rendered}"
        );
    }

    /// An unattributed open port is still an open port.
    #[test]
    fn a_socket_with_no_owner_still_gets_its_row() {
        let rendered = render(
            &table(vec![socket("0.0.0.0", 631, Exposure::Wildcard, None)]),
            firewall(FirewallMode::Unknown),
            &options(),
        );
        assert!(rendered.contains(":631"), "{rendered}");
        assert!(rendered.contains('—'), "{rendered}");
        assert!(
            rendered.contains("1 socket owned by other users"),
            "{rendered}"
        );
        assert!(rendered.contains("sudo netinspect listen"), "{rendered}");
    }

    #[test]
    fn only_somebody_elses_socket_names_its_owner() {
        let rendered = render(
            &table(vec![
                socket("0.0.0.0", 22, Exposure::Wildcard, Some(("sshd", 1, 0))),
                socket(
                    "0.0.0.0",
                    3000,
                    Exposure::Wildcard,
                    Some(("node", 8830, 501)),
                ),
            ]),
            firewall(FirewallMode::Unknown),
            &options(),
        );
        let sshd = rendered.lines().find(|l| l.contains("sshd")).unwrap();
        let node = rendered.lines().find(|l| l.contains("node")).unwrap();
        assert!(sshd.contains("root"), "{sshd:?}");
        assert!(!node.contains("maya"), "{node:?}");
    }

    #[test]
    fn an_ipv6_address_keeps_its_brackets() {
        let rendered = render(
            &table(vec![socket("::", 7000, Exposure::Wildcard, None)]),
            firewall(FirewallMode::Unknown),
            &options(),
        );
        assert!(rendered.contains("[::]:7000"), "{rendered}");
    }

    #[test]
    fn the_firewall_footer_hedges_and_disappears_when_unknown() {
        let sockets = table(vec![
            socket(
                "0.0.0.0",
                5432,
                Exposure::Wildcard,
                Some(("postgres", 1284, 501)),
            ),
            socket("0.0.0.0", 22, Exposure::Wildcard, Some(("sshd", 1, 0))),
        ]);

        let off = render(&sockets, firewall(FirewallMode::Off), &options());
        assert!(
            off.contains("the 2 exposed ports accept connections"),
            "{off}"
        );

        // The macOS firewall filters by application, not by port. This must
        // never be tightened into a claim that a port is closed.
        let on = render(&sockets, firewall(FirewallMode::On), &options());
        assert!(on.contains("may still be filtered per app"), "{on}");
        assert!(!on.contains("closed"), "{on}");

        let blocked = render(&sockets, firewall(FirewallMode::BlockAll), &options());
        assert!(blocked.contains("blocking all incoming"), "{blocked}");

        // Silence beats a guess: no row at all.
        let unknown = render(&sockets, firewall(FirewallMode::Unknown), &options());
        assert!(!unknown.contains("application firewall"), "{unknown}");
    }

    #[test]
    fn resolve_names_only_the_ports_people_recognise() {
        use crate::model::Protocol;
        assert_eq!(service_name(5432, Protocol::Tcp), Some("postgresql"));
        assert_eq!(service_name(5353, Protocol::Udp), Some("mdns"));
        // The same number means different things on the two protocols.
        assert_eq!(service_name(5353, Protocol::Tcp), None);
        // Anything unrecognised is left alone rather than guessed at.
        assert_eq!(service_name(49152, Protocol::Tcp), None);

        let sockets = table(vec![
            socket(
                "0.0.0.0",
                5432,
                Exposure::Wildcard,
                Some(("postgres", 1284, 501)),
            ),
            socket(
                "0.0.0.0",
                49152,
                Exposure::Wildcard,
                Some(("something", 2, 501)),
            ),
        ]);
        let mut with = options();
        with.resolve = true;
        let resolved = render(&sockets, firewall(FirewallMode::Unknown), &with);
        assert!(resolved.contains("postgresql"));
        assert!(
            !render(&sockets, firewall(FirewallMode::Unknown), &options()).contains("postgresql")
        );

        // The name lives in the address column, so it must be measured with
        // it — otherwise it runs straight into the process name.
        // The owner column starts at its mark, not at the name: the mark is
        // what keeps every row's name in one place.
        let header = resolved.lines().find(|l| l.contains("owner")).unwrap();
        let column = header.find("owner").unwrap();
        let mark = Theme::plain().glyphs.process;
        for line in resolved.lines().filter(|l| l.contains("postgres")) {
            let at = line.find(mark).unwrap();
            assert_eq!(at, column, "the owner column moved: {line:?}");
        }
    }

    #[test]
    fn nothing_listening_says_so() {
        let rendered = render(
            &table(Vec::new()),
            firewall(FirewallMode::Unknown),
            &options(),
        );
        assert!(rendered.contains("nothing is listening"), "{rendered}");
    }
}
