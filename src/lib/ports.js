// Exposed-ports / attack-surface data via Shodan InternetDB.
// Free, no API key. Returns previously-observed open ports, hostnames,
// CPEs, tags, and CVEs for a given IP. This is passive intelligence from
// Shodan's existing scans -- the extension performs NO active scanning of
// its own (a browser cannot open raw sockets anyway).

const INTERNETDB = "https://internetdb.shodan.io/";

// Best-effort service labels for the ports InternetDB commonly reports.
const WELL_KNOWN = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
  587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
  3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
  6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch",
  27017: "MongoDB",
};

export function serviceName(port) {
  return WELL_KNOWN[port] || null;
}

export async function lookupIP(ip) {
  const res = await fetch(INTERNETDB + encodeURIComponent(ip), {
    headers: { accept: "application/json" },
  });
  // InternetDB returns 404 when it has never seen the host -- a normal,
  // non-error outcome meaning "no exposed surface on record".
  if (res.status === 404) {
    return { ip, ports: [], hostnames: [], cpes: [], tags: [], vulns: [], seen: false };
  }
  if (!res.ok) {
    throw new Error(`InternetDB lookup failed (HTTP ${res.status})`);
  }
  const data = await res.json();
  const ports = (data.ports || []).slice().sort((a, b) => a - b);
  return {
    ip: data.ip || ip,
    ports: ports.map((p) => ({ port: p, service: serviceName(p) })),
    hostnames: data.hostnames || [],
    cpes: data.cpes || [],
    tags: data.tags || [],
    vulns: data.vulns || [],
    seen: true,
  };
}
