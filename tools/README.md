# tools

## `anonymise-capture.py`

Rewrites the identifying values in a captured report — addresses, MAC
addresses, the SSID, the search domain — so a capture can go into a README, an
issue or a design review without publishing somebody's network.

```
netinspect --no-color > capture.txt
tools/anonymise-capture.py capture.txt "MySSID" "corp.local"
```

Two rules make it usable rather than merely safe:

- **Every replacement is the same length as what it replaces**, so no column
  moves. The point of a real capture is that its alignment is real, and a
  screenshot with the columns shifted is worse than a synthetic one.
- **The prefix that decides an address's reach survives.** `192.168.x.y` stays
  `192.168`, `10.x` stays `10`, `fe80::` stays link-local. netinspect colours
  addresses by reach, so scrambling that prefix would make the capture lie
  about the very thing it is demonstrating.

Escape sequences are never touched, and it refuses rather than silently
truncating if a replacement would change a line's length.
