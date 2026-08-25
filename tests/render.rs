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
        system_timezone: Some("Europe/Budapest".to_owned()),
        public_age: None,
        edge: None,
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

fn stage(ok: bool, ms: Option<u64>) -> Stage {
    Stage { ok, ms }
}

fn online() -> Reachability {
    Reachability {
        link: Some(stage(true, None)),
        gateway: Some(stage(true, Some(2))),
        dns: Some(stage(true, Some(11))),
        http: Some(HttpStage {
            ok: true,
            ms: Some(38),
            status: Some(204),
        }),
        state: ReachabilityState::Online,
        captive_portal: None,
    }
}

#[test]
fn reachability_online() {
    let mut snapshot = full();
    snapshot.reachability = Some(online());
    insta::assert_snapshot!(human::render(&snapshot, &options(80)));
}

#[test]
fn reachability_captive_portal() {
    let mut snapshot = full();
    snapshot.reachability = Some(Reachability {
        http: Some(HttpStage {
            ok: true,
            ms: Some(24),
            status: Some(302),
        }),
        state: ReachabilityState::CaptivePortal,
        captive_portal: Some(CaptivePortal {
            login_url: "http://wifi.example.net/login".to_owned(),
        }),
        ..online()
    });
    insta::assert_snapshot!(human::render(&snapshot, &options(80)));
}

/// The rule this whole design exists for: a stage that was never attempted is
/// not a failed stage, and must not be drawn as one.
#[test]
fn a_stage_that_was_never_attempted_is_not_drawn_as_a_failure() {
    let mut snapshot = full();
    snapshot.reachability = Some(Reachability {
        link: Some(stage(true, None)),
        gateway: Some(stage(true, Some(2))),
        dns: Some(stage(false, Some(2000))),
        http: None,
        state: ReachabilityState::DnsFailure,
        captive_portal: None,
    });
    let rendered = human::render(&snapshot, &options(80));

    let ladder = rendered
        .lines()
        .find(|line| line.contains("link"))
        .expect("the ladder is drawn");
    // dns failed and is crossed; http was never tried and gets the pending dot.
    assert!(ladder.contains("dns ✗"), "{ladder:?}");
    assert!(ladder.contains("http ·"), "{ladder:?}");
    assert_eq!(ladder.matches('✗').count(), 1, "{ladder:?}");
    insta::assert_snapshot!(rendered);
}

#[test]
fn reachability_link_down() {
    let mut snapshot = full();
    snapshot.reachability = Some(Reachability {
        link: Some(stage(false, None)),
        gateway: None,
        dns: None,
        http: None,
        state: ReachabilityState::LinkDown,
        captive_portal: None,
    });
    let rendered = human::render(&snapshot, &options(80));
    let ladder = rendered
        .lines()
        .find(|line| line.contains("link"))
        .expect("the ladder is drawn");
    // Three untried stages, and the one that failed is crossed, not dotted.
    assert_eq!(ladder.matches('·').count(), 3, "{ladder:?}");
    assert!(ladder.contains("link ✗"), "{ladder:?}");
    insta::assert_snapshot!(rendered);
}

#[test]
fn reachability_narrow_drops_the_timings() {
    let mut snapshot = full();
    snapshot.reachability = Some(online());
    let rendered = human::render(&snapshot, &options(48));
    assert!(!rendered.contains(" ms"), "{rendered}");
    insta::assert_snapshot!(rendered);
}

/// Port 80 filtered while the internet is reachable. Saying "offline" here
/// would be wrong, and so would saying nothing is in the way.
#[test]
fn a_filtered_web_is_online_with_a_different_explanation() {
    let mut snapshot = full();
    snapshot.reachability = Some(Reachability {
        http: Some(HttpStage {
            ok: false,
            ms: Some(2000),
            status: None,
        }),
        ..online()
    });
    let rendered = human::render(&snapshot, &options(80));
    assert!(rendered.contains("online"), "{rendered}");
    assert!(rendered.contains("filtered"), "{rendered}");
}

fn public_address() -> PublicAddress {
    PublicAddress {
        ipv4: Some("84.21.7.113".to_owned()),
        ipv6: None,
        asn: Some("AS5483".to_owned()),
        org: Some("Magyar Telekom".to_owned()),
        city: Some("Budapest".to_owned()),
        region: Some("Budapest".to_owned()),
        country: Some("HU".to_owned()),
        latitude: Some(47.4980),
        longitude: Some(19.0400),
        accuracy_km: None,
        timezone: Some("Europe/Budapest".to_owned()),
        timezone_matches_system: Some(true),
        via_vpn: None,
        cached_at: Some("2026-08-25T14:19:02+02:00".to_owned()),
    }
}

#[test]
fn public_address_section() {
    let mut snapshot = full();
    snapshot.reachability = Some(online());
    snapshot.public = Some(public_address());
    insta::assert_snapshot!(human::render(&snapshot, &options(100)));
}

/// The loudest thing the report can say. A tunnel is up and the traffic is not
/// going through it.
#[test]
fn a_vpn_leak_is_named_on_the_address_it_concerns() {
    let mut snapshot = full();
    snapshot.reachability = Some(online());
    snapshot.public = Some(PublicAddress {
        via_vpn: Some(false),
        ..public_address()
    });
    let rendered = human::render(&snapshot, &options(100));
    assert!(rendered.contains("not routed through VPN"), "{rendered}");
    insta::assert_snapshot!(rendered);
}

#[test]
fn a_working_tunnel_says_so_on_the_same_row() {
    let mut snapshot = full();
    snapshot.public = Some(PublicAddress {
        via_vpn: Some(true),
        ..public_address()
    });
    let rendered = human::render(&snapshot, &options(100));
    let row = rendered.lines().find(|l| l.contains("84.21.7.113")).unwrap();
    assert!(row.contains("via VPN"), "{row:?}");
}

/// Nothing is claimed without evidence: with no record of this machine without
/// a tunnel there is nothing to compare against, so the row says nothing.
#[test]
fn without_a_baseline_the_address_row_carries_no_verdict() {
    let mut snapshot = full();
    snapshot.public = Some(public_address());
    let rendered = human::render(&snapshot, &options(100));
    let row = rendered.lines().find(|l| l.contains("84.21.7.113")).unwrap();
    assert!(!row.contains("VPN"), "{row:?}");
}

#[test]
fn a_timezone_mismatch_names_the_system_clock() {
    let mut snapshot = full();
    snapshot.public = Some(PublicAddress {
        timezone: Some("America/New_York".to_owned()),
        timezone_matches_system: Some(false),
        ..public_address()
    });
    let rendered = human::render(&snapshot, &options(100));
    assert!(rendered.contains("system clock is Europe/Budapest"), "{rendered}");
}

/// A provider that stops returning a field must not take the section down with
/// it: every row is independent.
#[test]
fn an_address_with_nothing_else_still_renders() {
    let mut snapshot = full();
    snapshot.public = Some(PublicAddress {
        asn: None,
        org: None,
        city: None,
        region: None,
        country: None,
        latitude: None,
        longitude: None,
        timezone: None,
        timezone_matches_system: None,
        ..public_address()
    });
    let rendered = human::render(&snapshot, &options(100));
    assert!(rendered.contains("PUBLIC ADDRESS"), "{rendered}");
    assert!(rendered.contains("84.21.7.113"), "{rendered}");
    for absent in ["network", "location", "timezone"] {
        assert!(
            !rendered.contains(&format!("    {absent}")),
            "{absent} row should be omitted:\n{rendered}"
        );
    }
}

/// Section titles have to line up when two blocks share a row.
#[test]
fn packed_section_titles_share_a_line() {
    let mut snapshot = full();
    snapshot.reachability = Some(online());
    snapshot.public = Some(public_address());
    let rendered = human::render(&snapshot, &options(120));

    let titles = rendered
        .lines()
        .find(|l| l.contains("DNS") && l.contains("REACHABILITY"))
        .expect("DNS and REACHABILITY share a row");
    // And the row above them is blank, not a title pushed a line high.
    let index = rendered.lines().position(|l| l == titles).unwrap();
    assert!(
        rendered.lines().nth(index - 1).is_some_and(|l| l.trim().is_empty()),
        "{rendered}"
    );
}

/// Watch mode does not re-fetch the address every tick, so the heading has to
/// say how old the one on screen is.
#[test]
fn a_carried_public_address_says_its_age() {
    let mut snapshot = full();
    snapshot.public = Some(public_address());

    let fresh = human::render(&snapshot, &options(100));
    assert!(fresh.contains("PUBLIC ADDRESS"), "{fresh}");
    assert!(!fresh.contains("ago"), "{fresh}");

    let mut aged = options(100);
    aged.public_age = Some("3m ago".to_owned());
    let rendered = human::render(&snapshot, &aged);
    let heading = rendered
        .lines()
        .find(|line| line.contains("PUBLIC ADDRESS"))
        .expect("the heading");
    assert!(heading.contains("3m ago"), "{heading:?}");
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

/// The content follows the terminal between its two bounds, and nothing may
/// spill past the edge it settled on — at any width, with or without the
/// reachability section.
#[test]
fn no_line_overruns_the_content_edge() {
    for width in [200, 140, 100, 96, 80, 66, 48, 38] {
        let edge = netinspect::render::layout::content_edge(width);
        let mut snapshot = full();
        snapshot.reachability = Some(online());
        for snapshot in [full(), snapshot] {
            let rendered = human::render(&snapshot, &options(width));
            for line in rendered.lines() {
                let columns = line.chars().count();
                assert!(
                    columns <= edge,
                    "at width {width} (edge {edge}), {columns} columns: {line:?}"
                );
            }
        }
    }
}

/// The point of the width: rows that had to stack at 62 columns stop stacking
/// as soon as they fit, and the short sections pair up instead of leaving half
/// the terminal empty.
#[test]
fn extra_width_is_spent_on_unstacking_not_on_padding() {
    let mut snapshot = full();
    snapshot.reachability = Some(online());

    let narrow = human::render(&snapshot, &options(62));
    let wide = human::render(&snapshot, &options(120));
    assert!(
        wide.lines().count() < narrow.lines().count(),
        "wide:\n{wide}\nnarrow:\n{narrow}"
    );

    // The radio's second line is a consequence of the width, not a fixture.
    assert!(narrow.contains("Wi-Fi 6"), "{narrow}");
    let radio = wide
        .lines()
        .find(|line| line.contains("network"))
        .expect("a radio row");
    assert!(radio.contains("Wi-Fi 6"), "{radio:?}");
    assert!(radio.contains("1200 Mb/s"), "{radio:?}");

    // DNS and REACHABILITY share a row rather than stacking.
    assert!(
        wide.lines().any(|l| l.contains("DNS") && l.contains("REACHABILITY")),
        "{wide}"
    );
    assert!(
        !narrow.lines().any(|l| l.contains("DNS") && l.contains("REACHABILITY")),
        "{narrow}"
    );
}

#[test]
fn paired_sections_keep_the_timings_under_their_stages() {
    let mut snapshot = full();
    snapshot.reachability = Some(online());
    let wide = human::render(&snapshot, &options(120));

    let ladder = wide.lines().find(|l| l.contains("link ✓")).expect("ladder");
    let timings = wide.lines().find(|l| l.contains("11 ms")).expect("timings");

    // Columns, not bytes: the ladder is full of multi-byte glyphs, and byte
    // offsets would agree with each other while agreeing with nothing on
    // screen.
    let column_of = |line: &str, needle: &str| {
        let byte = line.find(needle).expect("present");
        line[..byte].chars().count()
    };
    for stage in ["gateway", "dns", "http"] {
        let column = column_of(ladder, stage);
        let under = timings.chars().nth(column);
        assert!(
            under.is_some_and(|c| c.is_ascii_digit()),
            "{stage} timing is not under its name (column {column}, found {under:?}):\n{ladder}\n{timings}"
        );
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
