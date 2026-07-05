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

// Reject hosts we can't meaningfully recon (loopback, single-label intranet
// names, empties). Bare IPv4 literals are allowed.
export function isScannableHost(hostname) {
  if (!hostname) return false;
  if (hostname === "localhost") return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return true;
  return hostname.includes(".");
}
