#!/usr/bin/env python3
"""Rewrite identifying values in a captured terminal report.

    netinspect --no-color > capture.txt
    tools/anonymise-capture.py capture.txt "MySSID" "corp.local"

A real report is a map of the machine that produced it: its LAN, its DNS
servers, its search domain, its VPN's inner address, its Wi-Fi network and its
MAC addresses. None of that belongs in a README, a screenshot or a bug report,
and it is easy to paste without noticing.

Two rules, both load-bearing:

* Replacements are the SAME LENGTH as what they replace, so every column stays
  exactly where it was — the point of the capture is that the alignment is real.
* Escape sequences are never touched. Anchoring on word boundaries does not
  work here: an escape ends in `m`, so an address right after one has no word
  boundary before it. The text is split on escapes and only the visible runs
  are rewritten.
"""
import hashlib, pathlib, re, sys

ESCAPE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
MAC = re.compile(r'(?<![0-9a-f:])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f:])')
IPV6 = re.compile(r'(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])')
IPV4 = re.compile(r'(?<![0-9.])\d{1,3}(?:\.\d{1,3}){3}(?![0-9.])')

def digest(token, salt=""):
    return int(hashlib.sha256((salt + token).encode()).hexdigest(), 16)

def scramble_hex(text, salt):
    h = digest(text, salt)
    out = []
    for ch in text:
        if ch in "0123456789abcdefABCDEF":
            out.append("0123456789abcdef"[h % 16])
            h //= 7
        else:
            out.append(ch)
    return "".join(out)

def fake_ipv4(match):
    text = match.group(0)
    # These identify nobody.
    if text.startswith(("127.", "169.254.", "0.", "255.")):
        return text
    parts = text.split(".")
    h = digest(text)
    # Keep whatever decides the address's reach. The capture is a page about
    # colour meaning: a scrambled 192.168 painted teal would be a lie about the
    # very thing it is demonstrating.
    keep = 0
    if parts[0] == "10":
        keep = 1
    elif parts[0] == "192" and parts[1] == "168":
        keep = 2
    elif parts[0] == "172" and parts[1].isdigit() and 16 <= int(parts[1]) < 32:
        keep = 2
    elif parts[0] == "224":
        keep = 1

    out = []
    for index, part in enumerate(parts):
        if index < keep:
            out.append(part)
            continue
        # Same digit count, and still a valid octet: 192.168.683.5 would be
        # nonsense on a page about reading addresses.
        width = len(part)
        value = {3: 100 + h % 156, 2: 10 + h % 90}.get(width, h % 10)
        h //= 97
        out.append(str(value))
    return ".".join(out)

def looks_like_a_clock(text):
    # HH:MM:SS has two colons, no `::`, and every group is two digits.
    groups = text.split(":")
    return len(groups) == 3 and all(len(g) == 2 and g.isdigit() for g in groups)

def fake_ipv6(match):
    text = match.group(0)
    if text in ("::", "::1") or looks_like_a_clock(text):
        return text
    # Same rule as IPv4: the prefix that decides reach survives, so link-local
    # and unique-local addresses still read as what they are.
    head, _, rest = text.partition(":")
    lowered = head.lower()
    if lowered.startswith(("fe8", "fe9", "fea", "feb", "fc", "fd")):
        return head + ":" + scramble_hex(rest, "v6")
    return scramble_hex(text, "v6")

def sanitise_run(text, ssid, search_domain):
    text = MAC.sub(lambda m: scramble_hex(m.group(0), "mac"), text)
    text = IPV6.sub(fake_ipv6, text)
    text = IPV4.sub(fake_ipv4, text)
    if ssid:
        text = text.replace(ssid, "Kekesteto"[: len(ssid)].ljust(len(ssid), "x"))
    if search_domain:
        text = text.replace(
            search_domain, "example.lan"[: len(search_domain)].ljust(len(search_domain), "x")
        )
    return text

def sanitise(text, ssid, search_domain):
    out, last = [], 0
    for escape in ESCAPE.finditer(text):
        out.append(sanitise_run(text[last : escape.start()], ssid, search_domain))
        out.append(escape.group(0))
        last = escape.end()
    out.append(sanitise_run(text[last:], ssid, search_domain))
    return "".join(out)

def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    target = pathlib.Path(sys.argv[1])
    ssid = sys.argv[2] if len(sys.argv) > 2 else ""
    search_domain = sys.argv[3] if len(sys.argv) > 3 else ""

    paths = sorted(target.iterdir()) if target.is_dir() else [target]
    for path in paths:
        if not path.is_file():
            continue
        before = path.read_text()
        after = sanitise(before, ssid, search_domain)
        # A replacement of a different length would move every column after it,
        # and the whole point of a capture is that its alignment is real.
        assert len(before) == len(after), f"{path.name}: length changed"
        path.write_text(after)
        print(f"anonymised {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
