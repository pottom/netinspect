# Releasing

A release is cut by tagging. `.github/workflows/release.yml` does the rest, and
everything it does is reproducible from the tag alone.

```
# Cargo.toml and the tag must agree; the workflow refuses if they do not.
git tag v0.4.0 && git push origin v0.4.0
```

---

## Before the first release: the signing key

**`netinspect update` refuses to run until this exists.** `verify::PUBLIC_KEY`
is empty in a fresh checkout, and an update path that cannot check what it
downloads is worse than none at all — so it fails closed rather than skipping
the check.

```
brew install minisign
minisign -G -p netinspect.pub -s netinspect.key
```

- Paste the key line from `netinspect.pub` into `PUBLIC_KEY` in
  `src/update/verify.rs`. It ships inside every binary; that is the point, and
  it is why the key is **never fetched over the network**.
- Put the contents of `netinspect.key` into the `MINISIGN_SECRET_KEY` repository
  secret, then delete the local file. Anyone holding it can hand every user of
  this tool a binary it will install without complaint.
- Keep an offline copy somewhere you would keep a backup code. Losing it means
  every installed copy stops accepting updates, and there is no recovery short
  of a new key and a manual reinstall.

## The other secrets

Signing and notarisation are what stop Gatekeeper blocking the first launch on
a machine that downloaded the archive through a browser.

| Secret | What it is |
|---|---|
| `APPLE_CERTIFICATE_P12` | Developer ID Application certificate, exported as `.p12` and base64-encoded |
| `APPLE_CERTIFICATE_PASSWORD` | The password used for that export |
| `APPLE_SIGNING_IDENTITY` | e.g. `Developer ID Application: Your Name (TEAMID)` |
| `APPLE_NOTARY_ISSUER_ID` | App Store Connect API issuer UUID |
| `APPLE_NOTARY_KEY_ID` | App Store Connect API key id |
| `APPLE_NOTARY_KEY` | The `.p8` private key, contents verbatim |
| `MINISIGN_SECRET_KEY` | From the step above |

## What a release contains

One binary per architecture, **not** a universal one. The distribution is
already target-aware — `install.sh` picks by `uname -m` and `update` asks for
the archive its own triple implies — so a fat binary would only mean every user
downloading an architecture they cannot run:

```
netinspect-0.4.0-aarch64-apple-darwin.tar.gz
netinspect-0.4.0-aarch64-apple-darwin.tar.gz.minisig
netinspect-0.4.0-x86_64-apple-darwin.tar.gz
netinspect-0.4.0-x86_64-apple-darwin.tar.gz.minisig
SHA256SUMS
```

The checksum catches a download that broke; the signature catches one that was
swapped. Only the second is a security property.

## Homebrew

`packaging/netinspect.rb` goes in a tap (`homebrew-netinspect`). After a
release, update `version` and both `sha256` values from `SHA256SUMS`.

A brew-installed copy is detected from its path — `…/Cellar/netinspect/…` — and
`netinspect update` tells the user to run `brew upgrade netinspect` rather than
replacing a file a package manager believes it owns.

## Checking a release by hand

```
minisign -V -p netinspect.pub -m netinspect-0.4.0-aarch64-apple-darwin.tar.gz
shasum -a 256 -c SHA256SUMS --ignore-missing
```
