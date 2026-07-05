// DNS-over-HTTPS lookups via Cloudflare (RFC 8484 JSON API).
// Works from an extension service worker with host_permissions granted.

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

// Record types we surface in the dashboard, in display order.
export const RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"];

// Numeric rdata type -> label, for pretty-printing answers.
const TYPE_NAMES = {
  1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX",
  16: "TXT", 28: "AAAA", 257: "CAA",
};

async function queryType(name, type) {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetch(url, {
    headers: { accept: "application/dns-json" },
  });
  if (!res.ok) {
    throw new Error(`DoH ${type} lookup failed (HTTP ${res.status})`);
  }
  const data = await res.json();
  const answers = Array.isArray(data.Answer) ? data.Answer : [];
  return answers.map((a) => ({
    type: TYPE_NAMES[a.type] || String(a.type),
    ttl: a.TTL,
    value: a.data,
  }));
}

// Look up all record types for a hostname. Failures on a single type are
// captured per-record so one bad type never sinks the whole panel.
export async function lookupAll(hostname) {
  const results = {};
  await Promise.all(
    RECORD_TYPES.map(async (type) => {
      try {
        results[type] = await queryType(hostname, type);
      } catch (err) {
        results[type] = { error: err.message };
      }
    })
  );
  return results;
}

// Resolve the first IPv4 address for a hostname (used to seed the port scan).
export async function resolveIPv4(hostname) {
  const answers = await queryType(hostname, "A");
  const a = answers.find((r) => r.type === "A");
  return a ? a.value : null;
}
