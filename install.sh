#!/bin/sh
# netinspect installer.
#
#   curl -fsSL https://raw.githubusercontent.com/pottom/netinspect/main/install.sh | sh
#
# This script pipes into a shell, which is a thing worth being careful about.
# So: it downloads over TLS, verifies the archive against the release's
# published SHA256SUMS before unpacking anything, and — if minisign is
# available — verifies the signature too. It installs one file and touches
# nothing else. Read it first; that is the point of it being short.
set -eu

REPO="pottom/netinspect"
# The key that signs releases, the same one compiled into the binary.
MINISIGN_PUBLIC_KEY="RWR8d8Kv1w59idBR1l9XvA1Z9+/P3YIw7QTH47qpdrNfwoDo+JE/UPaQ"

say() { printf '%s\n' "$*" >&2; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || die "netinspect is macOS only (this is $(uname -s))"

case "$(uname -m)" in
  arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
  x86_64)        TARGET="x86_64-apple-darwin" ;;
  *)             die "unsupported architecture $(uname -m)" ;;
esac

# Somewhere on PATH that this user can write, without asking for root.
if [ -n "${NETINSPECT_INSTALL_DIR:-}" ]; then
  DEST="$NETINSPECT_INSTALL_DIR"
elif [ -w "/usr/local/bin" ] 2>/dev/null; then
  DEST="/usr/local/bin"
else
  DEST="$HOME/.local/bin"
fi

TAG="${NETINSPECT_VERSION:-}"
if [ -z "$TAG" ]; then
  TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
fi
[ -n "$TAG" ] || die "could not work out the latest release"
VERSION="${TAG#v}"

ARCHIVE="netinspect-$VERSION-$TARGET.tar.gz"
BASE="https://github.com/$REPO/releases/download/$TAG"

TMP=$(mktemp -d)
# Leave nothing behind, whichever way this ends.
trap 'rm -rf "$TMP"' EXIT INT TERM

say "netinspect $TAG for $TARGET"

curl -fsSL "$BASE/$ARCHIVE" -o "$TMP/$ARCHIVE" || die "could not download $ARCHIVE"
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS" || die "could not download SHA256SUMS"

# The checksum catches a download that broke.
EXPECTED=$(grep " $ARCHIVE\$" "$TMP/SHA256SUMS" | awk '{print $1}')
[ -n "$EXPECTED" ] || die "$ARCHIVE is not listed in SHA256SUMS"
ACTUAL=$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] || die "$ARCHIVE does not match its published checksum"
say "checksum ok"

# The signature catches one that was swapped. Only this is a security property,
# and it needs a tool this script will not install for you.
if command -v minisign >/dev/null 2>&1 && [ -n "$MINISIGN_PUBLIC_KEY" ]; then
  curl -fsSL "$BASE/$ARCHIVE.minisig" -o "$TMP/$ARCHIVE.minisig" ||
    die "could not download the signature"
  minisign -V -P "$MINISIGN_PUBLIC_KEY" -m "$TMP/$ARCHIVE" -x "$TMP/$ARCHIVE.minisig" >/dev/null ||
    die "the release signature does not verify"
  say "signature ok"
else
  say "note: minisign is not installed, so only the checksum was verified"
  say "      brew install minisign, then run this again for the stronger check"
fi

tar -xzf "$TMP/$ARCHIVE" -C "$TMP" || die "the archive could not be unpacked"
[ -f "$TMP/netinspect" ] || die "the archive did not contain netinspect"

mkdir -p "$DEST"
install -m 755 "$TMP/netinspect" "$DEST/netinspect" ||
  die "could not install into $DEST — set NETINSPECT_INSTALL_DIR to somewhere you can write"

# It arrived over the network, so it carries a quarantine flag.
xattr -d com.apple.quarantine "$DEST/netinspect" 2>/dev/null || true

say "installed $DEST/netinspect"
case ":$PATH:" in
  *":$DEST:"*) ;;
  *) say "note: $DEST is not on your PATH" ;;
esac
"$DEST/netinspect" --version >&2
