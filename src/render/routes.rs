//! The `routes` table.
//!
//! Column widths are measured from the data rather than fixed: IPv6
//! destinations routinely outgrow anything chosen in advance. When the table
//! will not fit, the gateway column truncates first — **a destination is never
//! truncated**, because a half-printed prefix is worse than no column at all.

use crate::model::{Family, Interface, InterfaceKind, Route, RouteSummary};

use super::layout::{rule, Line, MARGIN, RAIL_COL};
use super::reach;
use super::theme::{Role, Theme};

/// Rows are indented one step past the family heading.
const ROW_COL: usize = 6;
/// Two spaces between columns, so a full cell never touches its neighbour.
const GAP: usize = 2;

/// The kernel's own bookkeeping: entries it cloned for hosts this machine has
/// spoken to, multicast, and the link-local prefix every interface carries. A
/// typical machine has forty routes and maybe eight that anyone came to see.
pub fn is_interesting(route: &Route) -> bool {
    let has = |flag: &str| route.flags_decoded.iter().any(|f| f == flag);
    if has("was-cloned") || has("multicast") {
        return false;
    }
    !route.destination.starts_with("fe80::/")
}

/// The two conditions worth surfacing under a routing table.
pub fn summarise(shown: &[Route], all: &[Route], interfaces: &[Interface]) -> RouteSummary {
    let tunnels: Vec<&str> = interfaces
        .iter()
        .filter(|iface| iface.kind == InterfaceKind::Vpn && iface.is_active())
        .map(|iface| iface.name.as_str())
        .collect();

    // A tunnel that carries some routes but not the default one is only
    // handling part of the traffic, which is rarely obvious and often not what
    // the person at the keyboard believes.
    let split_tunnel = tunnels.iter().any(|tunnel| {
        let owns_routes = all
            .iter()
            .any(|route| route.interface.as_deref() == Some(tunnel));
        let owns_default = all
            .iter()
            .any(|route| route.is_default && route.interface.as_deref() == Some(tunnel));
        owns_routes && !owns_default
    });

    RouteSummary {
        total: shown.len(),
        default_gateways: all.iter().filter(|route| route.is_default).count(),
        split_tunnel,
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub theme: Theme,
    pub edge: usize,
}

struct Widths {
    destination: usize,
    gateway: usize,
    interface: usize,
}

/// Measured across **every** route, not per family.
///
/// Sizing each block to its own contents puts the ipv4 and ipv6 columns in
/// different places, and a reader comparing the two tables then has to find
/// the columns again halfway down the page. One measurement costs the ipv4
/// block some blank space and buys a single grid.
fn widths(routes: &[Route], edge: usize) -> Widths {
    let longest = |f: fn(&Route) -> usize, header: usize| {
        routes.iter().map(f).max().unwrap_or(0).max(header) + GAP
    };
    let mut widths = Widths {
        destination: longest(|r| r.destination.chars().count(), "destination".len()),
        gateway: longest(
            |r| r.gateway.as_deref().unwrap_or("").chars().count(),
            "gateway".len(),
        ),
        interface: longest(
            |r| r.interface.as_deref().unwrap_or("").chars().count(),
            "iface".len(),
        ),
    };

    // Flags are five or six characters; the row has to end somewhere.
    let available = edge.saturating_sub(ROW_COL - 1 + 6);
    let total = widths.destination + widths.gateway + widths.interface;
    if total > available {
        // Take it out of the gateway, never the destination.
        let over = total - available;
        widths.gateway = widths
            .gateway
            .saturating_sub(over)
            .max("gateway".len() + GAP);
    }
    widths
}

pub fn render(routes: &[Route], summary: &RouteSummary, options: &Options) -> String {
    let theme = &options.theme;
    let mut out: Vec<String> = Vec::new();

    let widths = widths(routes, options.edge);
    for family in [Family::Inet, Family::Inet6] {
        let block: Vec<&Route> = routes.iter().filter(|r| r.family == family).collect();
        if block.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(String::new());
        }
        out.push(heading(theme, family, options.edge));
        out.push(String::new());

        out.push(header_row(theme, &widths));
        for route in block {
            out.push(row(theme, route, &widths));
        }
    }

    if out.is_empty() {
        let mut line = Line::new();
        line.pad_to(RAIL_COL);
        line.push(theme, Role::Faint, "no routes");
        out.push(line.finish());
    }

    out.push(String::new());
    out.push(rule(theme, options.edge));
    out.push(footer(theme, summary));

    let mut text = out.join("\n");
    text.push('\n');
    text
}

/// `ipv4 ────────…` — a family heading, not one of the report's sections.
fn heading(theme: &Theme, family: Family, edge: usize) -> String {
    let name = match family {
        Family::Inet => "ipv4",
        Family::Inet6 => "ipv6",
    };
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    line.push(theme, Role::Dim, name);
    line.space(1);
    let used = line.width() - MARGIN;
    line.push(
        theme,
        Role::Rule,
        &theme.glyphs.rule.repeat(edge.saturating_sub(MARGIN + used)),
    );
    line.finish()
}

fn header_row(theme: &Theme, widths: &Widths) -> String {
    let mut line = Line::new();
    line.pad_to(ROW_COL);
    line.push(theme, Role::Dim, "destination");
    line.pad_to(ROW_COL + widths.destination);
    line.push(theme, Role::Dim, "gateway");
    line.pad_to(ROW_COL + widths.destination + widths.gateway);
    line.push(theme, Role::Dim, "iface");
    line.pad_to(ROW_COL + widths.destination + widths.gateway + widths.interface);
    line.push(theme, Role::Dim, "flags");
    line.finish()
}

fn row(theme: &Theme, route: &Route, widths: &Widths) -> String {
    let mut line = Line::new();
    line.pad_to(ROW_COL);

    // `default` is the only destination that is not an address, and the only
    // one in bright.
    if route.is_default {
        line.push(theme, Role::Bright, &route.destination);
    } else {
        match route.destination.split_once('/') {
            Some((address, prefix)) => {
                line.push(theme, reach::classify(address).role(), address);
                line.push(theme, Role::Faint, &format!("/{prefix}"));
            }
            None => {
                let role = reach::classify(&route.destination).role();
                line.push(theme, role, &route.destination);
            }
        }
    }

    line.pad_to(ROW_COL + widths.destination);
    if let Some(gateway) = &route.gateway {
        // An address gateway says where the traffic goes, so it is coloured by
        // reach. `link#12` and a hardware address say only "out of here".
        let role = match route.gateway_kind {
            crate::model::GatewayKind::Address => reach::classify(gateway).role(),
            _ => Role::Faint,
        };
        let room = widths.gateway.saturating_sub(GAP);
        let text = truncate(gateway, room, theme);
        line.push(theme, role, &text);
    }

    line.pad_to(ROW_COL + widths.destination + widths.gateway);
    if let Some(interface) = &route.interface {
        line.push(theme, Role::Body, interface);
    }

    line.pad_to(ROW_COL + widths.destination + widths.gateway + widths.interface);
    // Flags are reference material, not the point.
    line.push(theme, Role::Faint, &route.flags);

    if let Some(seconds) = route.expires_in_seconds {
        line.space(1);
        line.push(theme, Role::Faint, &format!("expires in {seconds}s"));
    }

    line.finish()
}

fn truncate(text: &str, room: usize, theme: &Theme) -> String {
    if text.chars().count() <= room || room == 0 {
        return text.to_owned();
    }
    let ellipsis = if theme.glyphs.rule == "-" {
        "..."
    } else {
        "…"
    };
    let keep = room.saturating_sub(ellipsis.chars().count());
    text.chars().take(keep).chain(ellipsis.chars()).collect()
}

fn footer(theme: &Theme, summary: &RouteSummary) -> String {
    let mut line = Line::new();
    line.pad_to(RAIL_COL);
    let count = if summary.total == 1 {
        "route"
    } else {
        "routes"
    };
    line.push(theme, Role::Bright, &format!("{} {count}", summary.total));

    let mut notes: Vec<String> = Vec::new();
    // Two default gateways is a real condition and rarely an intended one.
    if summary.default_gateways > 1 {
        notes.push(format!("{} default gateways", summary.default_gateways));
    }
    if summary.split_tunnel {
        notes.push("split tunnel active".to_owned());
    }
    if !notes.is_empty() {
        line.space(3);
        line.push(
            theme,
            Role::Faint,
            &notes.join(&format!(" {} ", theme.glyphs.sep)),
        );
    }
    line.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GatewayKind;

    fn route(destination: &str, flags: &[&str]) -> Route {
        Route {
            family: Family::Inet,
            destination: destination.to_owned(),
            is_default: destination == "default",
            gateway: None,
            gateway_kind: GatewayKind::None,
            interface: None,
            flags: String::new(),
            flags_decoded: flags.iter().map(|f| (*f).to_owned()).collect(),
            expires_in_seconds: None,
        }
    }

    #[test]
    fn the_kernels_own_bookkeeping_is_hidden_by_default() {
        assert!(is_interesting(&route("192.168.1.0/24", &["up"])));
        // Cloned for a host this machine has spoken to.
        assert!(!is_interesting(&route(
            "192.168.1.42",
            &["up", "was-cloned"]
        )));
        assert!(!is_interesting(&route("224.0.0.0/4", &["up", "multicast"])));
        // Every interface has one of these and none of them is news.
        assert!(!is_interesting(&route("fe80::/64", &["up"])));
        // A specific link-local host route is not the prefix.
        assert!(is_interesting(&route("fe80::1", &["up"])));
    }

    fn interface(name: &str, kind: InterfaceKind) -> Interface {
        Interface {
            name: name.to_owned(),
            display_name: None,
            kind,
            status: crate::model::InterfaceStatus::Up,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            gateway: None,
            mac: None,
            mtu: None,
            dhcp: None,
            wifi: None,
            vpn: None,
            is_default_route: false,
        }
    }

    fn on(destination: &str, interface: &str, default: bool) -> Route {
        let mut route = route(destination, &["up"]);
        route.interface = Some(interface.to_owned());
        route.is_default = default;
        route
    }

    #[test]
    fn a_tunnel_with_some_routes_but_not_the_default_is_a_split_tunnel() {
        let interfaces = [
            interface("en0", InterfaceKind::Wifi),
            interface("utun4", InterfaceKind::Vpn),
        ];
        let all = [
            on("default", "en0", true),
            on("10.4.0.0/16", "utun4", false),
        ];
        let summary = summarise(&all, &all, &interfaces);
        assert!(summary.split_tunnel);
        assert_eq!(summary.default_gateways, 1);
        assert_eq!(summary.total, 2);
    }

    #[test]
    fn a_tunnel_that_owns_the_default_route_is_not_split() {
        let interfaces = [
            interface("en0", InterfaceKind::Wifi),
            interface("utun4", InterfaceKind::Vpn),
        ];
        let all = [
            on("default", "utun4", true),
            on("10.4.0.0/16", "utun4", false),
        ];
        assert!(!summarise(&all, &all, &interfaces).split_tunnel);
    }

    #[test]
    fn an_idle_tunnel_with_leftover_routes_is_not_a_split_tunnel() {
        // The interface is down; whatever the table still says about it is not
        // a live condition to warn about.
        let mut idle = interface("utun9", InterfaceKind::Vpn);
        idle.status = crate::model::InterfaceStatus::Inactive;
        let interfaces = [interface("en0", InterfaceKind::Wifi), idle];
        let all = [
            on("default", "en0", true),
            on("10.9.0.0/16", "utun9", false),
        ];
        assert!(!summarise(&all, &all, &interfaces).split_tunnel);
    }

    #[test]
    fn the_total_counts_what_is_shown_but_the_gateways_count_them_all() {
        let interfaces = [interface("en0", InterfaceKind::Wifi)];
        let all = [
            on("default", "en0", true),
            on("default", "en5", true),
            on("192.168.1.42", "en0", false),
        ];
        let shown = &all[..2];
        let summary = summarise(shown, &all, &interfaces);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.default_gateways, 2);
    }

    #[test]
    fn both_families_share_one_grid() {
        // A reader comparing the two tables must not have to find the columns
        // again halfway down the page.
        let mut v4 = route("10.0.0.0/8", &[]);
        v4.family = Family::Inet;
        v4.gateway = Some("10.0.0.1".to_owned());
        v4.interface = Some("en0".to_owned());
        let mut v6 = route("2001:db8:aaaa:bbbb::/64", &[]);
        v6.family = Family::Inet6;
        v6.gateway = Some("fe80::1%en0".to_owned());
        v6.interface = Some("en0".to_owned());

        let rendered = render(
            &[v4, v6],
            &RouteSummary {
                total: 2,
                default_gateways: 0,
                split_tunnel: false,
            },
            &Options {
                theme: Theme::plain(),
                edge: 96,
            },
        );

        let headers: Vec<&str> = rendered
            .lines()
            .filter(|line| line.contains("destination"))
            .collect();
        assert_eq!(headers.len(), 2, "one header per family");
        assert_eq!(headers[0], headers[1], "the two grids must be identical");

        // And the rows land on it: the gateway starts at the same column in
        // both families, which is the thing a reader actually relies on.
        let column_of =
            |line: &str, needle: &str| line.find(needle).map(|byte| line[..byte].chars().count());
        let v4_gateway = rendered
            .lines()
            .find_map(|line| column_of(line, "10.0.0.1"))
            .expect("the ipv4 gateway");
        let v6_gateway = rendered
            .lines()
            .find_map(|line| column_of(line, "fe80::1%en0"))
            .expect("the ipv6 gateway");
        assert_eq!(v4_gateway, v6_gateway);
        assert_eq!(Some(v4_gateway), column_of(headers[0], "gateway"));
    }

    #[test]
    fn columns_are_measured_from_the_data() {
        let mut long = route("2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff/128", &[]);
        long.gateway = Some("fe80::1%en0".to_owned());
        long.interface = Some("en0".to_owned());
        let widths = widths(std::slice::from_ref(&long), 96);
        assert_eq!(widths.destination, long.destination.chars().count() + GAP);
        assert_eq!(
            widths.gateway,
            long.gateway.as_ref().unwrap().chars().count() + GAP
        );
    }

    #[test]
    fn a_column_never_shrinks_below_its_own_heading() {
        let widths = widths(&[route("10.0.0.0/8", &[])], 96);
        assert!(widths.destination >= "destination".len() + GAP);
        assert!(widths.gateway >= "gateway".len() + GAP);
        assert!(widths.interface >= "iface".len() + GAP);
    }

    #[test]
    fn the_gateway_gives_way_first_and_the_destination_never_does() {
        let mut wide = route("2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff/128", &[]);
        wide.gateway = Some("2001:db8:1111:2222:3333:4444:5555:6666".to_owned());
        wide.interface = Some("utun3".to_owned());

        let narrow = widths(&[wide.clone()], 62);
        assert_eq!(
            narrow.destination,
            wide.destination.chars().count() + GAP,
            "a destination must never be squeezed"
        );
        assert!(narrow.gateway < wide.gateway.as_ref().unwrap().chars().count() + GAP);
    }

    #[test]
    fn truncation_marks_itself() {
        let theme = Theme::plain();
        assert_eq!(truncate("192.168.1.1", 20, &theme), "192.168.1.1");
        assert_eq!(truncate("2001:db8::dead:beef", 10, &theme), "2001:db8:…");
        // The ASCII glyph set has no ellipsis.
        assert_eq!(
            truncate("2001:db8::dead:beef", 10, &Theme::ascii_plain()),
            "2001:db..."
        );
    }

    #[test]
    fn the_footer_only_reports_conditions_that_hold() {
        let theme = Theme::plain();
        let quiet = footer(
            &theme,
            &RouteSummary {
                total: 9,
                default_gateways: 1,
                split_tunnel: false,
            },
        );
        assert_eq!(quiet.trim(), "9 routes");

        let loud = footer(
            &theme,
            &RouteSummary {
                total: 9,
                default_gateways: 2,
                split_tunnel: true,
            },
        );
        assert!(loud.contains("2 default gateways"));
        assert!(loud.contains("split tunnel active"));

        // And it counts.
        let one = footer(
            &theme,
            &RouteSummary {
                total: 1,
                default_gateways: 1,
                split_tunnel: false,
            },
        );
        assert_eq!(one.trim(), "1 route");
    }
}
