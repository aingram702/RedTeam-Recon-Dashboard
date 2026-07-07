# Chrome Web Store — Listing Content

Everything below is copy-paste ready for the Chrome Web Store Developer
Dashboard. Character limits noted where the store enforces them.

---

## Product name
`≤ 75 chars`

```
RedTeam Recon Dashboard
```

## Summary (short description)
`≤ 132 chars`

```
Passive recon in one click: WHOIS/RDAP, DNS, technology fingerprint, and known exposed ports for the site in your active tab.
```

## Category

```
Developer Tools
```

## Language

```
English (United States)
```

---

## Detailed description
`≤ 16,000 chars`

```
RedTeam Recon Dashboard puts a full first-pass reconnaissance profile of any
website one click away. Open a site, click the toolbar icon, and a compact
dashboard aggregates four kinds of intelligence about the current tab — no API
keys, no accounts, and no setup.

━━ WHAT YOU GET ━━

• WHOIS / RDAP — registrar, creation / update / expiry dates, EPP status codes,
  nameservers, and DNSSEC state, pulled live over RDAP (the modern, HTTPS-based
  successor to port-43 WHOIS).

• DNS — A, AAAA, CNAME, MX, NS, TXT, SOA, and CAA records, resolved over
  DNS-over-HTTPS.

• Technology stack — CMS, JavaScript frameworks and libraries, analytics and
  tag managers, CDN, web server, and server-side language, fingerprinted from
  the page's own signals and response headers.

• Exposed ports & attack surface — publicly known open ports (with service
  labels), detected products (CPEs), known CVEs, and tags for the site's
  resolved IP address, sourced from Shodan's InternetDB.

Results stream into the dashboard panel-by-panel, so the fast lookups appear
instantly while slower ones fill in.

━━ PASSIVE BY DESIGN ━━

This extension performs NO active scanning. A browser cannot open raw network
sockets, and by design the extension never attempts to. "Exposed ports" come
from Shodan's existing, internet-wide scan data — not from probing the target.
Every data source is a read-only public API.

━━ SAFE WITH INTERNAL TARGETS ━━

Built for security professionals who work inside corporate networks:

• Private, loopback, link-local, CGNAT, and reserved hosts (10.x, 172.16–31.x,
  192.168.x, 127.x, *.local, *.corp, *.internal, …) are refused before any
  network request, so internal hostnames never leak to third-party services.

• If a public hostname resolves to a private IP (split-horizon DNS), the port
  lookup is skipped before the address would be sent to Shodan.

• The technology probe reads cookie NAMES only — never cookie values.

• Minimal permissions: activeTab (not broad host access), an explicit
  Content-Security-Policy, and only three external hosts contacted.

━━ HOW IT WORKS ━━

When you click the icon, the extension reads the active tab's URL, injects a
one-shot probe to gather technology signals, and queries three free public
services:

  • rdap.org               → WHOIS / RDAP registration data
  • cloudflare-dns.com     → DNS records (DNS-over-HTTPS)
  • internetdb.shodan.io   → publicly known open ports & CVEs

Nothing is stored, and no data is ever sent to the developer.

━━ WHO IT'S FOR ━━

Penetration testers, bug-bounty hunters, blue-teamers, SOC analysts, and web
developers who want a fast, at-a-glance recon profile without juggling half a
dozen CLI tools or websites.

━━ AUTHORIZED USE ONLY ━━

Use this tool only against assets you own or are explicitly authorized to
assess. It surfaces publicly available information; you are responsible for
complying with all applicable laws and policies.

Open source. No trackers. No analytics. No accounts.
```

---

## Single purpose description
(Privacy practices tab)

```
RedTeam Recon Dashboard has one purpose: to display passive reconnaissance
information — WHOIS/RDAP registration data, DNS records, a technology
fingerprint, and publicly known exposed ports — about the website in the
user's active browser tab, to support authorized security assessment.
```

---

## Permission justifications
(Privacy practices tab — one field per permission)

**activeTab**
```
Used only when the user clicks the toolbar icon. It lets the extension read the
current tab's URL (to look up that site's WHOIS, DNS, and port data) and run the
technology-fingerprint probe on that page. It grants no access to other tabs and
no access to browsing history.
```

**scripting**
```
Injects a single, one-shot fingerprint probe into the active tab when the user
clicks the icon. The probe reads technology signals from the page (JavaScript
globals, the meta generator tag, script/link URLs, cookie names, and response
headers) so the extension can identify the site's technology stack. It runs only
on the tab the user explicitly invokes it on.
```

**Host permission: https://rdap.org/**
```
To query public domain-registration data (WHOIS/RDAP) for the current site's
registrable domain.
```

**Host permission: https://cloudflare-dns.com/**
```
To resolve public DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA) for the
current site using DNS-over-HTTPS.
```

**Host permission: https://internetdb.shodan.io/**
```
To look up publicly known open ports, CPEs, and CVEs for the current site's
resolved IP address (passive data from Shodan's existing scans).
```

**Remote code**
```
No. The extension executes no remotely hosted code. All logic ships inside the
package; the only network activity is fetching JSON data from the three public
APIs listed above.
```

---

## Data usage disclosures
(Privacy practices tab — "What user data do you plan to collect?")

The developer collects **no** user data. Nothing is stored and nothing is sent
to any server operated by the developer. To function, the extension transmits
only the following to the three third-party public APIs, and only when the user
clicks the icon:

| Data | Sent to | Why |
| --- | --- | --- |
| Active tab's hostname / registrable domain | rdap.org, cloudflare-dns.com | WHOIS + DNS lookup |
| Site's resolved IP address | internetdb.shodan.io | Exposed-ports lookup |

No page contents, URLs paths/queries, form data, cookies values, credentials,
personal information, or browsing history are transmitted.

**Certifications (check all three):**
- ☑ I do not sell or transfer user data to third parties, outside of the approved use cases.
- ☑ I do not use or transfer user data for purposes unrelated to my item's single purpose.
- ☑ I do not use or transfer user data to determine creditworthiness or for lending purposes.

**Privacy policy URL:** _(host `store/PRIVACY.md` and paste its public URL here — see PRIVACY.md)_

---

## Notes for reviewers
(Optional field)

```
No login or test account is required. Click the toolbar icon on any public
https website (e.g. https://example.com) and the four panels populate from
public APIs. On a private/internal host (e.g. http://192.168.1.1) the extension
intentionally refuses external recon to avoid leaking internal network data.
```

---

## Graphical assets checklist

| Asset | Required size | File |
| --- | --- | --- |
| Store icon | 128×128 | `../icons/icon128.png` |
| Screenshot 1 (overview) | 1280×800 | `assets/screenshot-1-overview.png` |
| Screenshot 2 (WHOIS & DNS) | 1280×800 | `assets/screenshot-2-whois-dns.png` |
| Screenshot 3 (exposed ports) | 1280×800 | `assets/screenshot-3-ports.png` |
| Screenshot 4 (tech stack) | 1280×800 | `assets/screenshot-4-tech.png` |
| Screenshot 5 (privacy guard) | 1280×800 | `assets/screenshot-5-privacy.png` |
| Small promo tile | 440×280 | `assets/promo-small-440x280.png` |
| Marquee promo tile | 1400×560 | `assets/promo-marquee-1400x560.png` |

Regenerate the tiles/screenshots any time with `node store/render.mjs`.
```
