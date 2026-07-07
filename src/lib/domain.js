// Hostname helpers shared by the service worker. Kept dependency-free so they
// can be unit-tested outside the extension runtime.

// A small set of common two-label public suffixes. Not exhaustive (the real
// Public Suffix List has thousands of entries), but covers the cases a recon
// pass hits most often; RDAP bootstrap tolerates an imperfect trim.
const TWO_LABEL_TLDS = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "net.au",
  "org.au", "co.nz", "co.za", "com.br", "com.mx", "co.in",
]);

// Reduce a hostname to its registrable ("apex") domain for RDAP queries.
export function registrableDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join(".");
  if (TWO_LABEL_TLDS.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

// Reserved / private-use top-level labels. Reconning these would ship internal
// hostnames to third-party services (DoH, RDAP, Shodan), so they are excluded.
const NON_PUBLIC_TLDS = new Set([
  "local", "localhost", "internal", "intranet", "lan", "home", "corp",
  "localdomain", "test", "example", "invalid", "onion",
]);

// True only for a globally-routable public IPv4 literal. Private, loopback,
// link-local, CGNAT, benchmarking, documentation, multicast, and reserved
// ranges all return false -- we must never disclose these to external APIs.
export function isPublicIPv4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip || "");
  if (!m) return false;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return false;
  const [a, b, c] = o;
  if (a === 0 || a === 10 || a === 127) return false;          // this-net, private, loopback
  if (a === 169 && b === 254) return false;                     // link-local
  if (a === 172 && b >= 16 && b <= 31) return false;            // private
  if (a === 192 && b === 168) return false;                     // private
  if (a === 100 && b >= 64 && b <= 127) return false;           // CGNAT
  if (a === 192 && b === 0 && c === 2) return false;            // TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return false;        // benchmarking
  if (a === 198 && b === 51 && c === 100) return false;         // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return false;          // TEST-NET-3
  if (a >= 224) return false;                                   // multicast + reserved + broadcast
  return true;
}

// Reject hosts we should not send to external recon services: loopback,
// single-label intranet names, reserved TLDs, and private/reserved IP
// literals. This is a privacy/data-exposure guard, not just a validity check --
// it runs before any network call so internal targets never leak.
export function isScannableHost(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase();
  if (h === "localhost") return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return isPublicIPv4(h);
  if (!h.includes(".")) return false; // single-label / intranet
  const tld = h.slice(h.lastIndexOf(".") + 1);
  if (NON_PUBLIC_TLDS.has(tld)) return false;
  return true;
}
