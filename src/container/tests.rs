use super::*;

use crate::model::{Exposure, Family, ProcessInfo, SocketEntry};

/// The shape the Engine API actually returns, taken from a running daemon.
const BODY: &[u8] = br#"[
  {"Names":["/dazzling_bouman"],"Image":"hashicorp/terraform-mcp-server:0.4.0","Ports":[]},
  {"Names":["/snow-logger"],"Image":"baistvan/snow-logger:latest",
   "Ports":[{"IP":"0.0.0.0","PrivatePort":3000,"PublicPort":3000,"Type":"tcp"},
            {"IP":"::","PrivatePort":3000,"PublicPort":3000,"Type":"tcp"}]},
  {"Names":["/buildx_buildkit_multiarch0"],"Image":"moby/buildkit:buildx-stable-1","Ports":[]}
]"#;

fn socket(address: &str, port: u16, process: Option<(&str, &str)>) -> SocketEntry {
    SocketEntry {
        protocol: Protocol::Tcp,
        family: if address.contains(':') {
            Family::Inet6
        } else {
            Family::Inet
        },
        address: address.to_owned(),
        port,
        state: "listen".to_owned(),
        exposure: Exposure::Wildcard,
        process: process.map(|(name, path)| ProcessInfo {
            name: name.to_owned(),
            pid: 87092,
            uid: 501,
            user: Some("maya".to_owned()),
            path: Some(path.to_owned()),
        }),
        container: None,
    }
}

#[test]
fn a_daemon_reply_yields_the_containers_it_lists() {
    let containers = parse(BODY);
    assert_eq!(containers.len(), 3);
    // The daemon's leading slash is its own namespace, not part of the name.
    assert_eq!(containers[1].name, "snow-logger");
    assert_eq!(containers[1].image, "baistvan/snow-logger:latest");
}

/// A container with nothing published owns no host port, so it must not be
/// able to claim one.
#[test]
fn a_container_that_publishes_nothing_carries_no_ports() {
    let containers = parse(BODY);
    assert!(containers[0].ports.is_empty());
    assert!(containers[2].ports.is_empty());
}

#[test]
fn a_dual_stack_publish_names_both_rows() {
    let containers = parse(BODY);
    let mut sockets = vec![socket("0.0.0.0", 3000, None), socket("::", 3000, None)];
    apply(&mut sockets, "orbstack", &containers);

    for entry in &sockets {
        let container = entry
            .container
            .as_ref()
            .expect("both rows are the same publish");
        assert_eq!(container.name.as_deref(), Some("snow-logger"));
        assert_eq!(container.runtime, "orbstack");
        assert_eq!(container.private_port, Some(3000));
    }
}

/// The published address is part of the mapping. Ignoring it swaps two
/// containers that share a port number on different addresses.
#[test]
fn two_containers_on_one_port_are_told_apart_by_address() {
    let body = br#"[
      {"Names":["/ipv4-only"],"Image":"a","Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]},
      {"Names":["/ipv6-only"],"Image":"b","Ports":[{"IP":"::","PrivatePort":90,"PublicPort":8080,"Type":"tcp"}]}
    ]"#;
    let mut sockets = vec![socket("0.0.0.0", 8080, None), socket("::", 8080, None)];
    apply(&mut sockets, "docker", &parse(body));

    let name = |i: usize| sockets[i].container.as_ref().unwrap().name.clone().unwrap();
    assert_eq!(name(0), "ipv4-only");
    assert_eq!(name(1), "ipv6-only");
}

/// A mapping with no address published on every address, and then the port is
/// all there is to go on.
#[test]
fn a_mapping_without_an_address_matches_on_the_port_alone() {
    let body = br#"[{"Names":["/any"],"Image":"a","Ports":[{"PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]}]"#;
    let mut sockets = vec![socket("127.0.0.1", 8080, None)];
    apply(&mut sockets, "docker", &parse(body));
    assert_eq!(
        sockets[0].container.as_ref().unwrap().name.as_deref(),
        Some("any")
    );
}

#[test]
fn the_protocol_has_to_agree() {
    let body = br#"[{"Names":["/u"],"Image":"a","Ports":[{"IP":"0.0.0.0","PrivatePort":53,"PublicPort":5353,"Type":"udp"}]}]"#;
    let mut sockets = vec![socket("0.0.0.0", 5353, None)];
    apply(&mut sockets, "docker", &parse(body));
    assert!(
        sockets[0].container.is_none(),
        "a tcp socket must not be claimed by a udp publish"
    );
}

#[test]
fn a_port_no_container_published_stays_unclaimed() {
    let mut sockets = vec![socket("0.0.0.0", 22, None)];
    apply(&mut sockets, "orbstack", &parse(BODY));
    assert!(sockets[0].container.is_none());
}

/// Garbage in, nothing out — never a panic, and never a partial list passed
/// off as the whole one.
#[test]
fn a_reply_that_is_not_a_container_list_yields_nothing() {
    assert!(parse(b"").is_empty());
    assert!(parse(b"not json").is_empty());
    assert!(parse(b"{}").is_empty());
    assert!(parse(br#"{"message":"permission denied"}"#).is_empty());
}

#[test]
fn the_forwarder_is_recognised_by_its_path() {
    let orbstack = "/Applications/OrbStack.app/Contents/Frameworks/OrbStack Helper.app/Contents/MacOS/OrbStack Helper";
    assert_eq!(
        forwarder(Some(orbstack), "OrbStack Helper"),
        Some("orbstack")
    );
    assert_eq!(
        forwarder(
            Some("/Applications/Docker.app/Contents/MacOS/com.docker.backend"),
            "x"
        ),
        Some("docker")
    );
}

/// The path is what tells a runtime from something merely named like one.
#[test]
fn a_binary_that_is_only_called_docker_is_not_a_runtime() {
    assert_eq!(forwarder(Some("/Users/maya/bin/docker"), "docker"), None);
    assert_eq!(
        forwarder(Some("/usr/local/bin/hopscotch"), "hopscotch"),
        None
    );
    assert_eq!(forwarder(None, "OrbStack Helper"), None);
}

/// Helpers whose install path varies are matched by name instead.
#[test]
fn a_helper_with_no_stable_path_is_matched_by_name() {
    assert_eq!(forwarder(None, "com.docker.backend"), Some("docker"));
    assert_eq!(forwarder(None, "gvproxy"), Some("podman"));
    assert_eq!(forwarder(None, "vpnkit-bridge"), None);
}

#[test]
fn a_recognised_forwarder_says_container_without_naming_one() {
    let orbstack = "/Applications/OrbStack.app/Contents/MacOS/OrbStack Helper";
    let mut sockets = vec![socket("0.0.0.0", 3000, Some(("OrbStack Helper", orbstack)))];
    apply_forwarders(&mut sockets);

    let container = sockets[0].container.as_ref().unwrap();
    assert_eq!(container.runtime, "orbstack");
    assert!(
        container.name.is_none(),
        "an unnamed container must not be given a name"
    );
}

/// The fallback is weaker than the runtime's own answer and must never
/// replace it.
#[test]
fn the_fallback_never_overwrites_a_name_we_already_have() {
    let orbstack = "/Applications/OrbStack.app/Contents/MacOS/OrbStack Helper";
    let mut sockets = vec![socket("0.0.0.0", 3000, Some(("OrbStack Helper", orbstack)))];
    apply(&mut sockets, "orbstack", &parse(BODY));
    apply_forwarders(&mut sockets);
    assert_eq!(
        sockets[0].container.as_ref().unwrap().name.as_deref(),
        Some("snow-logger")
    );
}

/// A `tcp://` daemon can be on another machine, and following it would turn a
/// local inspection into a network call to a third party.
#[test]
fn a_tcp_docker_host_is_not_followed() {
    let paths = socket_paths(Some("tcp://10.0.0.5:2375"), None, None);
    assert_eq!(
        paths.len(),
        1,
        "only the well-known path remains: {paths:?}"
    );
    assert_eq!(paths[0].1, PathBuf::from("/var/run/docker.sock"));
}

#[test]
fn an_explicit_unix_socket_is_tried_first() {
    let paths = socket_paths(
        Some("unix:///tmp/mine.sock"),
        Some(std::path::Path::new("/home/maya")),
        None,
    );
    assert_eq!(paths[0].1, PathBuf::from("/tmp/mine.sock"));
}

/// A runtime's own socket must be reached before the generic path, which on
/// such a machine is a symlink to it — otherwise its containers get labelled
/// "docker".
#[test]
fn a_runtimes_own_socket_beats_the_symlink_that_points_at_it() {
    let paths = socket_paths(None, Some(std::path::Path::new("/home/maya")), None);
    let position = |runtime: &str| {
        paths
            .iter()
            .position(|(name, _)| *name == runtime)
            .expect("runtime is a candidate")
    };
    let generic = paths
        .iter()
        .position(|(_, path)| path.as_path() == std::path::Path::new("/var/run/docker.sock"))
        .unwrap();
    assert!(position("orbstack") < generic);
    assert!(position("colima") < generic);
}

/// Docker Desktop lists one mapping for a port its proxy forwards on both
/// families. The sibling row is the same publish, not an unnamed stranger.
#[test]
fn a_publish_listed_on_one_family_names_the_other_too() {
    let body = br#"[{"Names":["/web"],"Image":"nginx","Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]}]"#;
    let helper = ("com.docker.backend", "/Applications/Docker.app/x");
    let mut sockets = vec![
        socket("0.0.0.0", 8080, Some(helper)),
        socket("::", 8080, Some(helper)),
    ];
    resolve(&mut sockets, Some(("docker", &parse(body))));

    for entry in &sockets {
        assert_eq!(
            entry.container.as_ref().unwrap().name.as_deref(),
            Some("web"),
            "both halves of one publish carry the name"
        );
    }
}

/// Same port, different program — nothing to do with that container.
#[test]
fn a_different_process_on_the_same_port_is_not_the_same_publish() {
    let body = br#"[{"Names":["/web"],"Image":"nginx","Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}]}]"#;
    let mut sockets = vec![
        socket(
            "0.0.0.0",
            8080,
            Some(("com.docker.backend", "/Applications/Docker.app/x")),
        ),
        socket(
            "::",
            8080,
            Some(("something-else", "/usr/local/bin/something-else")),
        ),
    ];
    sockets[1].process.as_mut().unwrap().pid = 4242;
    resolve(&mut sockets, Some(("docker", &parse(body))));

    assert!(sockets[0].container.is_some());
    assert!(
        sockets[1].container.is_none(),
        "another program's socket must not inherit a container"
    );
}

/// The bug this rule exists for: a runtime's helper holds sockets of its own —
/// OrbStack's machine SSH port among them — and they are not containers.
#[test]
fn a_helpers_own_ports_are_not_marked_when_the_runtime_answered() {
    let orbstack = (
        "OrbStack Helper",
        "/Applications/OrbStack.app/Contents/MacOS/OrbStack Helper",
    );
    let mut sockets = vec![
        socket("0.0.0.0", 3000, Some(orbstack)),
        socket("127.0.0.1", 32222, Some(orbstack)),
    ];
    resolve(&mut sockets, Some(("orbstack", &parse(BODY))));

    assert_eq!(
        sockets[0].container.as_ref().unwrap().name.as_deref(),
        Some("snow-logger")
    );
    assert!(
        sockets[1].container.is_none(),
        "the runtime listed every published port, and this was not one of them"
    );
}

/// Only with no answer at all does the weaker source get to speak.
#[test]
fn the_forwarder_speaks_only_when_no_runtime_answered() {
    let orbstack = (
        "OrbStack Helper",
        "/Applications/OrbStack.app/Contents/MacOS/OrbStack Helper",
    );
    let mut sockets = vec![socket("127.0.0.1", 32222, Some(orbstack))];
    resolve(&mut sockets, None);

    let container = sockets[0].container.as_ref().unwrap();
    assert_eq!(container.runtime, "orbstack");
    assert!(container.name.is_none());
}
