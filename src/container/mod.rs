//! Naming the container behind a published port.
//!
//! On macOS a container never opens a socket on the host. The runtime runs a
//! Linux VM and forwards each published port through a helper process, so
//! `listen` sees `0.0.0.0:3000` owned by something like `OrbStack Helper` — a
//! process nobody started on purpose and whose name explains nothing. The
//! question a person actually has is *which container did this*.
//!
//! Two sources, in descending order of what they can tell us:
//!
//! 1. **The runtime's API socket.** Every runtime worth naming speaks the
//!    Docker Engine API on a unix socket, so one `GET /containers/json` gives
//!    the container's name, its image, and the port mapping. This names the
//!    container.
//! 2. **The forwarder's executable path.** When the socket is missing or
//!    unreadable, recognising the helper still establishes *that* the port
//!    belongs to a container, which is most of the value. It cannot say which.
//!
//! This module is core rather than platform code: the Engine API and the unix
//! socket are identical on Linux, and nothing here is macOS-specific.
//!
//! **Only unix sockets.** `DOCKER_HOST` may name a `tcp://` daemon, which can
//! be on another machine entirely. Following that would turn a local, read-only
//! inspection into a network call to a third party, so a `tcp://` host is
//! ignored rather than honoured.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::model::{ContainerRef, Protocol, SocketEntry};
use crate::parse::http;

/// The whole exchange is with a daemon on this machine. If it has not answered
/// in this long it is wedged, and `listen` is not the command to find that out
/// from.
const TIMEOUT: Duration = Duration::from_millis(400);

/// A daemon replying with more than this is not one we asked a question we
/// understand. Bounded because the peer chooses the length.
const MAX_BODY: usize = 4 * 1024 * 1024;

/// Pinned rather than negotiated: 1.41 is Docker 20.10 and older, and every
/// runtime below has spoken it for years. Asking for a newer version buys
/// nothing we read.
const ENDPOINT: &str = "/v1.41/containers/json";

/// A running container, reduced to what a port table needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub name: String,
    pub image: String,
    pub ports: Vec<PublishedPort>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedPort {
    /// `None` when the runtime published on every address.
    pub address: Option<&'static str>,
    pub public: u16,
    pub private: u16,
    pub protocol: Protocol,
}

/// Ask whichever runtime is reachable, and annotate the sockets it claims.
///
/// Silent on every failure by design: a machine with no container runtime is
/// the common case, not an error, and `listen` must render identically whether
/// or not a daemon happened to answer.
pub fn annotate(sockets: &mut [SocketEntry]) {
    let answer = query();
    resolve(
        sockets,
        answer
            .as_ref()
            .map(|(runtime, containers)| (runtime.as_str(), containers.as_slice())),
    );
}

/// Pure: decide what each socket knows, given whatever the runtime said.
///
/// The two sources are alternatives, not layers. When a daemon answered we
/// have the full list of published ports, and a helper's remaining sockets —
/// OrbStack's machine SSH port, Docker's own API socket — belong to the
/// runtime, not to a container. Running the forwarder fallback alongside a
/// good answer marks those as containers, which is a guess made in exactly the
/// place we had the truth.
fn resolve(sockets: &mut [SocketEntry], answer: Option<(&str, &[Container])>) {
    match answer {
        Some((runtime, containers)) => {
            apply(sockets, runtime, containers);
            same_publish(sockets);
        }
        // Nothing answered: recognising the helper is all that is left.
        None => apply_forwarders(sockets),
    }
}

/// Carry a match across to the other address family of the same publish.
///
/// A runtime is free to report one mapping for a port it forwards on both
/// families — Docker Desktop lists `0.0.0.0` and nothing for `::`, while its
/// proxy listens on both. The sibling row is the same publish by the same
/// helper, so it gets the same container.
fn same_publish(sockets: &mut [SocketEntry]) {
    // Collected first because the scan and the write cannot borrow at once.
    let known: Vec<(i32, u16, Protocol, ContainerRef)> = sockets
        .iter()
        .filter_map(|socket| {
            Some((
                socket.process.as_ref()?.pid,
                socket.port,
                socket.protocol,
                socket.container.clone()?,
            ))
        })
        .collect();

    for socket in sockets.iter_mut() {
        if socket.container.is_some() {
            continue;
        }
        let Some(process) = &socket.process else {
            continue;
        };
        // Same helper, same port, same protocol — the other half of one
        // publish. A different pid is a different program and none of this
        // container's business.
        if let Some((.., container)) = known.iter().find(|(pid, port, protocol, _)| {
            *pid == process.pid && *port == socket.port && *protocol == socket.protocol
        }) {
            socket.container = Some(container.clone());
        }
    }
}

/// The runtime that answered, and what it is running.
fn query() -> Option<(String, Vec<Container>)> {
    for (runtime, path) in candidates() {
        let Some(body) = ask(&path) else { continue };
        // A daemon that answered but has nothing running is still the daemon:
        // stop here rather than trying the next candidate, which on this
        // machine is usually the same socket under another name.
        return Some((runtime.to_owned(), parse(&body)));
    }
    None
}

/// Where to look, filtered down to what is actually there.
fn candidates() -> Vec<(&'static str, PathBuf)> {
    let mut paths = socket_paths(
        std::env::var("DOCKER_HOST").ok().as_deref(),
        std::env::var_os("HOME").map(PathBuf::from).as_deref(),
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .as_deref(),
    );
    paths.retain(|(_, path)| path.exists());
    paths
}

/// The candidate list, most specific first.
///
/// Takes its environment as arguments rather than reading it: a function that
/// reads the process environment can only be tested by mutating it, and this
/// one has rules worth testing.
///
/// `/var/run/docker.sock` comes last among the well-known paths because on a
/// machine running OrbStack or Colima it is a symlink to theirs, and reaching
/// it first would label their containers "docker".
fn socket_paths(
    docker_host: Option<&str>,
    home: Option<&std::path::Path>,
    runtime_dir: Option<&std::path::Path>,
) -> Vec<(&'static str, PathBuf)> {
    let mut paths: Vec<(&'static str, PathBuf)> = Vec::new();

    // An explicit unix socket beats every guess below. A `tcp://` host is
    // ignored, not followed — see this module's header.
    if let Some(path) = docker_host.and_then(|host| host.strip_prefix("unix://")) {
        paths.push(("docker", PathBuf::from(path)));
    }

    if let Some(home) = home {
        paths.push(("orbstack", home.join(".orbstack/run/docker.sock")));
        paths.push(("colima", home.join(".colima/default/docker.sock")));
        paths.push(("rancher", home.join(".rd/docker.sock")));
        paths.push(("docker", home.join(".docker/run/docker.sock")));
    }
    if let Some(runtime_dir) = runtime_dir {
        paths.push(("podman", runtime_dir.join("podman/podman.sock")));
    }
    paths.push(("docker", PathBuf::from("/var/run/docker.sock")));

    paths
}

/// One request, one bounded read, no retries.
fn ask(path: &PathBuf) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(path).ok()?;
    stream.set_read_timeout(Some(TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(TIMEOUT)).ok()?;

    // `Connection: close` so the daemon frames the body by closing, which is
    // the one framing that cannot leave us waiting for a chunk that never
    // comes.
    let request =
        format!("GET {ENDPOINT} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    stream.flush().ok()?;

    let mut raw = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                raw.extend_from_slice(&buffer[..read]);
                if raw.len() > MAX_BODY {
                    return None;
                }
            }
            // A timeout mid-body is a short read, and the parser below decides
            // whether what arrived is usable.
            Err(_) => break,
        }
    }

    let response = http::response(&raw)?;
    // 403 and 404 both happen — a socket we may not read, and a daemon that
    // does not speak this API. Neither is worth a word to the user.
    if response.status != 200 || !response.complete {
        return None;
    }
    Some(response.body)
}

/// What the Engine API calls a container. Only the fields we read.
#[derive(Deserialize)]
struct Wire {
    #[serde(default)]
    #[serde(rename = "Names")]
    names: Vec<String>,
    #[serde(default)]
    #[serde(rename = "Image")]
    image: String,
    #[serde(default)]
    #[serde(rename = "Ports")]
    ports: Vec<WirePort>,
}

#[derive(Deserialize)]
struct WirePort {
    #[serde(default)]
    #[serde(rename = "IP")]
    ip: String,
    #[serde(default)]
    #[serde(rename = "PublicPort")]
    public: Option<u16>,
    #[serde(default)]
    #[serde(rename = "PrivatePort")]
    private: u16,
    #[serde(default)]
    #[serde(rename = "Type")]
    kind: String,
}

/// Pure: the body in, containers out.
pub fn parse(body: &[u8]) -> Vec<Container> {
    let Ok(wire) = serde_json::from_slice::<Vec<Wire>>(body) else {
        return Vec::new();
    };
    wire.into_iter()
        .map(|container| Container {
            // The API returns names with a leading slash, which is an artefact
            // of the daemon's own namespace and not part of what anyone calls
            // the container.
            name: container
                .names
                .first()
                .map(|name| name.trim_start_matches('/').to_owned())
                .unwrap_or_default(),
            image: container.image,
            ports: container
                .ports
                .into_iter()
                .filter_map(|port| {
                    Some(PublishedPort {
                        // An unpublished port has no public side at all.
                        public: port.public?,
                        private: port.private,
                        protocol: match port.kind.as_str() {
                            "udp" => Protocol::Udp,
                            _ => Protocol::Tcp,
                        },
                        address: match port.ip.as_str() {
                            "0.0.0.0" => Some("0.0.0.0"),
                            "::" => Some("::"),
                            // An empty address means every address, and there is
                            // then nothing to match on but the port.
                            _ => None,
                        },
                    })
                })
                .collect(),
        })
        .collect()
}

/// Pure: attach each container to the sockets it published.
pub fn apply(sockets: &mut [SocketEntry], runtime: &str, containers: &[Container]) {
    for socket in sockets.iter_mut() {
        for container in containers {
            let matched = container.ports.iter().find(|port| {
                port.public == socket.port
                    && port.protocol == socket.protocol
                    // A published address must agree when the runtime gave
                    // one. Without this the IPv4 and IPv6 rows of a dual-stack
                    // publish both match every mapping, and a machine running
                    // two containers on the same port gets them swapped.
                    && port.address.is_none_or(|address| address == socket.address)
            });
            if let Some(port) = matched {
                socket.container = Some(ContainerRef {
                    runtime: runtime.to_owned(),
                    name: Some(container.name.clone()),
                    image: Some(container.image.clone()),
                    private_port: Some(port.private),
                });
                break;
            }
        }
    }
}

/// Pure: recognise the forwarder itself, for sockets no runtime claimed.
///
/// This is the fallback, and it is deliberately weaker: it establishes that a
/// container owns the port without naming it. Runs after `apply` so it never
/// overwrites a name we actually have.
pub fn apply_forwarders(sockets: &mut [SocketEntry]) {
    for socket in sockets.iter_mut() {
        if socket.container.is_some() {
            continue;
        }
        let Some(process) = &socket.process else {
            continue;
        };
        let Some(runtime) = forwarder(process.path.as_deref(), &process.name) else {
            continue;
        };
        socket.container = Some(ContainerRef {
            runtime: runtime.to_owned(),
            name: None,
            image: None,
            private_port: None,
        });
    }
}

/// Which runtime a port-forwarding helper belongs to, by executable path.
///
/// Path first, because it is the half that cannot be faked by accident: a
/// script called `docker` on someone's `PATH` is not a container runtime. The
/// name is consulted only for the helpers whose paths vary.
///
/// Verified against a running install: **OrbStack** only. The rest are written
/// from their documented layouts and have not been observed here — treat a bug
/// report against one of them as a report against this list, not against the
/// matching logic.
fn forwarder(path: Option<&str>, name: &str) -> Option<&'static str> {
    const BY_PATH: [(&str, &str); 5] = [
        ("/Applications/OrbStack.app/", "orbstack"),
        ("/Applications/Docker.app/", "docker"),
        ("/Applications/Rancher Desktop.app/", "rancher"),
        ("/Applications/Podman Desktop.app/", "podman"),
        ("/.colima/", "colima"),
    ];
    if let Some(path) = path {
        if let Some((_, runtime)) = BY_PATH.iter().find(|(prefix, _)| path.contains(prefix)) {
            return Some(runtime);
        }
    }

    // Helpers that live wherever the package manager put them, so only the
    // name is stable. Kept exact rather than fuzzy: `vpnkit` is Docker's,
    // `vpnkit-bridge` is not necessarily.
    match name {
        "com.docker.backend" | "com.docker.vpnkit" | "vpnkit" | "docker-proxy" => Some("docker"),
        "gvproxy" => Some("podman"),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
