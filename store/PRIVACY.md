# Privacy Policy — RedTeam Recon Dashboard

_Last updated: 2026-07-07_

RedTeam Recon Dashboard ("the extension") is a browser extension that displays
passive reconnaissance information about the website in your active browser tab.
This policy explains exactly what data the extension handles.

## Summary

- The developer **collects nothing**. There are no accounts, no analytics, no
  trackers, and no server operated by the developer.
- Nothing you do in the extension is stored or logged anywhere off your device.
- To function, the extension sends only the current site's **hostname/domain**
  and its **resolved IP address** to three third-party public APIs, and only
  when you click the toolbar icon.

## What the extension accesses

When you click the extension's toolbar icon on a tab, it:

1. Reads that tab's URL to determine the hostname and registrable domain.
2. Injects a one-time probe into that page to read technology-fingerprint
   signals: JavaScript global names, the `<meta name="generator">` tag,
   script/stylesheet URLs, **cookie names** (never cookie values), and the
   document's response headers.

This happens only on the tab you explicitly invoke, only on your click, and only
for as long as it takes to build the dashboard. The extension does not read
other tabs, does not run in the background, and does not access your browsing
history.

## Data sent to third parties

To retrieve recon data, the extension makes read-only HTTPS requests to:

| Service | Data sent | Purpose | Provider policy |
| --- | --- | --- | --- |
| `rdap.org` | site's registrable domain | WHOIS/RDAP registration data | https://rdap.org |
| `cloudflare-dns.com` | site's hostname | DNS records (DNS-over-HTTPS) | https://www.cloudflare.com/privacypolicy/ |
| `internetdb.shodan.io` | site's resolved IP address | publicly known open ports & CVEs | https://www.shodan.io/legal/privacy |

No URL paths or query strings, page contents, form data, cookie values,
credentials, or personal information are transmitted. Requests are governed by
each provider's own privacy policy, linked above.

## Protection of internal / private targets

To avoid disclosing internal network information, the extension refuses to
perform external lookups for private, loopback, link-local, CGNAT, and reserved
addresses and top-level domains (for example `10.x`, `172.16–31.x`, `192.168.x`,
`127.x`, `*.local`, `*.corp`, `*.internal`). If a public hostname resolves to a
private IP address, the exposed-ports lookup is skipped so that address is never
sent to a third-party service.

## Data storage and retention

The extension stores no data. It does not use `chrome.storage`, cookies, or any
other persistence mechanism. All results live only in the popup while it is open
and are discarded when it closes.

## Data selling and sharing

The developer does not sell, rent, or transfer any user data. The only data
sharing that occurs is the functional API traffic described above.

## Changes to this policy

Material changes will be reflected in this document with an updated date.

## Contact

Questions about this policy can be raised as an issue on the project's public
repository.
