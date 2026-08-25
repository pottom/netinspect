//! Golden tests for the human report.
//!
//! The renderer is pure, so every shape of report is reachable from here — no
//! network, no hardware, no privileges. A change in spacing, colour role or
//! wording shows up as a diff rather than as a surprise on someone's terminal.

use netinspect::model::*;
use netinspect::render::human::{self, Options};
use netinspect::render::theme::{ColorMode, Palette, Theme, ASCII, UNICODE};

fn options(width: usize) -> Options {
    Options {
        theme: Theme::plain(),
        width,
        clock: "14:22:07 CEST".to_owned(),
        all: false,
        ipv4_only: false,
        ipv6_only: false,
        only_interface: None,
    }
}

fn wifi_interface(ssid: Option<&str>, source: Option<SsidSource>) -> Interface {
    Interface {
        name: "en0".to_owned(),
        display_name: Some("Wi-Fi".to_owned()),
        kind: InterfaceKind::Wifi,
        status: InterfaceStatus::Connected,
        ipv4: vec![Ipv4Entry {
            address: "192.168.1.24".to_owned(),
            prefix_len: 24,
            source: AddressSource::Dhcp,
        }],
        ipv6: vec![Ipv6Entry {
            address: "fe80::1c4d:8a2f:9b01:3e77".to_owned(),
            prefix_len: 64,
            scope: Ipv6Scope::Link,
        }],
        gateway: Some("192.168.1.1".to_owned()),
        mac: Some("a4:83:e7:2d:11:9c".to_owned()),
        mtu: Some(1500),
        dhcp: Some(DhcpLease {
            expires_at: None,
            seconds_remaining: None,
        }),
        wifi: Some(WifiDetail {
            ssid: ssid.map(str::to_owned),
            ssid_source: source,
            rssi_dbm: Some(-48),
            phy_mode: Some("802.11ax".to_owned()),
            rate_mbps: Some(1200),
        }),
        vpn: None,
        is_default_route: true,
    }
}

fn vpn_interface() -> Interface {
    Interface {
        name: "utun3".to_owned(),
        display_name: None,
        kind: InterfaceKind::Vpn,
        status: InterfaceStatus::Up,
        ipv4: vec![Ipv4Entry {
            address: "10.7.0.4".to_owned(),
            prefix_len: 32,
            source: AddressSource::Manual,
        }],
        ipv6: Vec::new(),
        gateway: None,
        mac: None,
        mtu: Some(1420),
        dhcp: None,
        wifi: None,
        vpn: Some(VpnDetail {
            protocol: Some("WireGuard".to_owned()),
            endpoint: Some("51.75.12.9:51820".to_owned()),
            last_handshake_seconds: Some(41),
        }),
        is_default_route: false,
    }
}

fn no_cable_interface() -> Interface {
    Interface {
        name: "en5".to_owned(),
        display_name: Some("Ethernet".to_owned()),
        kind: InterfaceKind::Ethernet,
        status: InterfaceStatus::NoCable,
        ipv4: Vec::new(),
        ipv6: Vec::new(),
        gateway: None,
        mac: Some("ac:de:48:00:11:22".to_owned()),
        mtu: Some(1500),
        dhcp: None,
        wifi: None,
        vpn: None,
        is_default_route: false,
    }
}

fn snapshot(interfaces: Vec<Interface>) -> Snapshot {
    Snapshot {
        schema: SCHEMA,
        version: "0.3.1".to_owned(),
        timestamp: "2026-08-25T14:22:07+02:00".to_owned(),
        interfaces,
        dns: DnsConfig {
            servers: vec!["1.1.1.1".to_owned(), "9.9.9.9".to_owned()],
            search_domains: vec!["otthon.lan".to_owned()],
            proxy: None,
            split_dns_scopes: 0,
        },
        reachability: None,
        public: None,
        update: None,
    }
}

fn full() -> Snapshot {
    snapshot(vec![
        wifi_interface(Some("Otthon_5G"), Some(SsidSource::CoreWlan)),
        vpn_interface(),
        no_cable_interface(),
    ])
}

#[test]
fn full_report() {
    insta::assert_snapshot!(human::render(&full(), &options(80)));
}

#[test]
fn narrow_terminal_stacks_instead_of_aligning() {
    insta::assert_snapshot!(human::render(&full(), &options(48)));
}

#[test]
fn ascii_fallback() {
    let mut options = options(80);
    options.theme = Theme::ascii_plain();
    insta::assert_snapshot!(human::render(&full(), &options));
}

#[test]
fn ssid_unavailable_says_so_rather_than_omitting_the_radio() {
    let snapshot = snapshot(vec![wifi_interface(None, None)]);
    insta::assert_snapshot!(human::render(&snapshot, &options(80)));
}

#[test]
fn a_scraped_ssid_is_always_disclosed() {
    let snapshot = snapshot(vec![wifi_interface(
        Some("Otthon_5G"),
        Some(SsidSource::HelperNetworksetup),
    )]);
    insta::assert_snapshot!(human::render(&snapshot, &options(80)));
}

#[test]
fn no_matching_interface() {
    let mut options = options(80);
    options.only_interface = Some("en99".to_owned());
    insta::assert_snapshot!(human::render(&full(), &options));
}

#[test]
fn all_shows_loopback_and_expands_inactive_interfaces() {
    let mut snapshot = full();
    snapshot.interfaces.push(Interface {
        name: "lo0".to_owned(),
        display_name: Some("Loopback".to_owned()),
        kind: InterfaceKind::Loopback,
        status: InterfaceStatus::Up,
        ipv4: vec![Ipv4Entry {
            address: "127.0.0.1".to_owned(),
            prefix_len: 8,
            source: AddressSource::Manual,
        }],
        ipv6: Vec::new(),
        gateway: None,
        mac: None,
        mtu: Some(16384),
        dhcp: None,
        wifi: None,
        vpn: None,
        is_default_route: false,
    });
    let mut options = options(80);
    options.all = true;
    insta::assert_snapshot!(human::render(&snapshot, &options));
}

#[test]
fn update_footer_appears_only_when_an_update_is_available() {
    let mut snapshot = full();
    snapshot.update = Some(UpdateInfo {
        current: "0.3.1".to_owned(),
        latest: Some("0.4.0".to_owned()),
        available: true,
    });
    insta::assert_snapshot!(human::render(&snapshot, &options(80)));
}

#[test]
fn a_current_version_prints_no_footer() {
    let mut snapshot = full();
    snapshot.update = Some(UpdateInfo {
        current: "0.3.1".to_owned(),
        latest: Some("0.3.1".to_owned()),
        available: false,
    });
    let rendered = human::render(&snapshot, &options(80));
    assert!(!rendered.contains("self-update"), "{rendered}");
}

#[test]
fn colour_never_leaks_into_a_plain_render() {
    for theme in [Theme::plain(), Theme::ascii_plain()] {
        let mut options = options(80);
        options.theme = theme;
        assert!(!human::render(&full(), &options).contains('\x1b'));
    }
}

#[test]
fn the_glyph_sets_produce_the_same_line_count() {
    // The ASCII fallback exists so a non-UTF-8 terminal keeps the layout; a
    // different number of rows would mean it is doing something else.
    let mut a = options(80);
    a.theme = Theme {
        color: ColorMode::None,
        palette: Palette::Dark,
        glyphs: UNICODE,
    };
    let mut b = options(80);
    b.theme = Theme {
        color: ColorMode::None,
        palette: Palette::Dark,
        glyphs: ASCII,
    };
    assert_eq!(
        human::render(&full(), &a).lines().count(),
        human::render(&full(), &b).lines().count()
    );
}

/// DESIGN.md §4: the content is 62 columns wide and nothing may exceed it.
#[test]
fn no_line_overruns_the_content_width() {
    for width in [80, 66, 48, 38] {
        let rendered = human::render(&full(), &options(width));
        for line in rendered.lines() {
            let columns = line.chars().count();
            assert!(
                columns <= 62,
                "at width {width}, {columns} columns: {line:?}"
            );
        }
    }
}

/// Hue encodes reach and nothing else. A LAN address and a public one must not
/// come out the same colour, and neither may be coloured by importance.
#[test]
fn addresses_are_coloured_by_reach_alone() {
    use netinspect::render::reach::classify;
    use netinspect::render::theme::Role;

    assert_eq!(classify("192.168.1.24").role(), Role::Lan);
    assert_eq!(classify("10.7.0.4").role(), Role::Lan);
    assert_eq!(classify("51.75.12.9").role(), Role::Public);
    assert_eq!(classify("127.0.0.1").role(), Role::Local);

    // The gateway is not more important than any other LAN address, so it must
    // not be painted differently.
    let mut coloured = options(80);
    coloured.theme = Theme {
        color: ColorMode::TrueColor,
        palette: Palette::Dark,
        glyphs: UNICODE,
    };
    let rendered = human::render(&full(), &coloured);
    let lan = "\x1b[38;2;69;187;160m";
    assert!(rendered.contains(&format!("{lan}192.168.1.1\x1b[0m")), "gateway");
    assert!(rendered.contains(&format!("{lan}192.168.1.24\x1b[0m")), "address");
}

/// The signal bars are a measurement, not a status. Green is reserved for a
/// probe that answered.
#[test]
fn signal_bars_are_never_green() {
    let mut coloured = options(80);
    coloured.theme = Theme {
        color: ColorMode::TrueColor,
        palette: Palette::Dark,
        glyphs: UNICODE,
    };
    let rendered = human::render(&full(), &coloured);
    let ok = "\x1b[38;2;140;201;111m";
    let bright = "\x1b[38;2;242;240;233m";
    assert!(rendered.contains(&format!("{bright}▇▇▇▇▇")), "bars are bright");
    assert!(!rendered.contains(&format!("{ok}▇")), "bars must not be ok-green");
}

/// Absent optional data is omitted, never printed as "unknown".
#[test]
fn an_unknown_vpn_protocol_prints_no_row() {
    let mut snapshot = full();
    if let Some(iface) = snapshot.interfaces.get_mut(1) {
        if let Some(vpn) = iface.vpn.as_mut() {
            vpn.protocol = None;
        }
    }
    let rendered = human::render(&snapshot, &options(80));
    assert!(!rendered.contains("unknown"), "{rendered}");
    assert!(!rendered.contains("protocol"), "{rendered}");
}
