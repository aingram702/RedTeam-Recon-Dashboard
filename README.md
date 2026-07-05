# RedTeam Recon Dashboard

A Chrome (Manifest V3) extension that aggregates reconnaissance data for the
site in the active tab into a single popup dashboard:

- **WHOIS / RDAP** — registrar, key dates, status codes, nameservers, DNSSEC
- **DNS** — A, AAAA, CNAME, MX, NS, TXT, SOA, CAA records
- **Technology stack** — CMS, frameworks, JS libraries, analytics, CDN, web
  server, and language fingerprints
- **Exposed ports & surface** — open ports, detected products (CPEs), known
  CVEs, and tags for the resolved IP

Results stream into the dashboard panel-by-panel, so fast lookups render
immediately while slower ones fill in.

---

## Authorized use only

This tool surfaces **passive** intelligence from public data sources. It does
**not** perform any active scanning — a browser cannot open raw sockets, and by
design the extension never tries to. "Exposed ports" come from Shodan's
*existing* internet-wide scan data (InternetDB), not from probing the target.

Only run it against assets you own or are explicitly authorized to assess.

## How it works

All lookups use free, key-less HTTPS services, so there is nothing to configure:

| Panel | Source | Endpoint |
| --- | --- | --- |
| WHOIS/RDAP | RDAP (RFC 9083) | `rdap.org` bootstrap → authoritative registry |
| DNS | DNS-over-HTTPS (RFC 8484) | `cloudflare-dns.com` |
| Ports/surface | Shodan InternetDB | `internetdb.shodan.io` |
| Tech stack | In-page fingerprinting | (local — no network) |

### Architecture

```
manifest.json            MV3 manifest (permissions, action, service worker)
src/
  popup.html/.css/.js    Dashboard UI; requests a scan, renders streamed panels
  background.js          Service worker; orchestrates the four lookups
  lib/
    dns.js               DoH client (all record types + IPv4 resolve)
    rdap.js              RDAP client + record normalization
    ports.js             InternetDB client
    fingerprints.js      Signature DB + matcher for the tech stack
    pageScan.js          Injected page probe (JS globals, markup, headers)
    domain.js            Registrable-domain / scannable-host helpers
icons/                   Generated PNG icons
tools/
  make_icons.py          Pure-stdlib PNG icon generator
  test.mjs               Unit tests (network stubbed)
```

The service worker fans out the four lookups concurrently and pushes each
result to the popup as it completes. Technology detection injects a
self-contained probe (`pageScan`) into the page's MAIN world to read JS
globals, `<meta generator>`, script URLs, cookie names, and — via a
same-origin `fetch` of the current document — response headers. Those signals
are matched against `fingerprints.js` in the service worker.

Only three external hosts are requested (see `host_permissions` in the
manifest); the extension asks for `activeTab` rather than broad host access, so
page inspection is scoped to the tab you explicitly invoke it on.

## Install (unpacked)

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select this repository's root directory
4. Pin the extension and click it on any `http(s)` page

## Development

Regenerate icons:

```bash
python3 tools/make_icons.py
```

Run the test suite (no network required — API responses are stubbed):

```bash
node tools/test.mjs
```

The tests cover the domain helpers, the fingerprint matcher, and the RDAP /
DNS / InternetDB parsers against payloads shaped like the real APIs.
