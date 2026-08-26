# src/container — naming the container behind a published port

Core code, not platform code: the Docker Engine API and its unix socket are
identical on Linux, and nothing here is macOS-specific.

## What this module is for

On macOS a container never opens a socket on the host. The runtime runs a Linux
VM and forwards each published port through a helper process, so `listen` sees
`0.0.0.0:3000` owned by something like `OrbStack Helper` — a process nobody
started on purpose, whose name explains nothing. The question the reader has is
*which container did this*.

## The two sources are alternatives, not layers

1. **The runtime's API socket** names the container. One
   `GET /v1.41/containers/json` gives the name, the image, and the mapping.
2. **The forwarder's executable path** establishes only *that* a container owns
   the port.

When a daemon answered we have the complete list of published ports, so a
helper's remaining sockets — OrbStack's machine SSH port, Docker's own API
socket — belong to the runtime and are **not** containers. Running the
forwarder fallback alongside a good answer marks those as containers, which is
a guess made exactly where the truth was available. `resolve` is the pure
function that holds this rule, and it is tested.

## Rules

- **Only unix sockets.** `DOCKER_HOST` may name a `tcp://` daemon on another
  machine. Following it would turn a local, read-only inspection into a network
  call to a third party. Ignore it.
- **Silent on every failure.** A machine with no container runtime is the common
  case, not an error. `listen` renders identically whether or not a daemon
  answered.
- **Bounded.** One request, one read, a 400 ms timeout, a 4 MB ceiling, no
  retries. The peer chooses the length; we choose the limit.
- **Never invent a name.** A recognised forwarder with no runtime answer yields
  `name: None`, and the renderer says "a container" rather than guessing which.
- **A runtime's own socket is tried before `/var/run/docker.sock`**, which on
  such a machine is a symlink to it. Reaching the symlink first labels their
  containers "docker".
- **Take the environment as arguments.** `socket_paths` is pure so its rules can
  be tested; a function that reads the process environment can only be tested by
  mutating it, and `unsafe { set_var }` is forbidden outside `src/sys/`.

## What is verified and what is not

The forwarder path table has been checked against a running install for
**OrbStack only**. Docker Desktop, Rancher, Podman and Colima entries are
written from their documented layouts. Treat a bug report against one of them as
a report against that list, not against the matching logic.

## Parsing

The HTTP response reader is in `src/parse/http.rs` — pure, over `&[u8]`, with
the framing cases (chunked, `Content-Length`, close-delimited, truncated)
reachable from tests with no socket. Only the JSON body is decoded here.
