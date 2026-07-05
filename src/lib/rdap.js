// WHOIS-equivalent data via RDAP (RFC 9083) over HTTPS.
// rdap.org acts as a bootstrap/redirector to the authoritative registry server.

const RDAP_BOOTSTRAP = "https://rdap.org/domain/";

// Reduce an RDAP domain object to the fields the dashboard shows.
function normalize(rdap) {
  const events = {};
  for (const ev of rdap.events || []) {
    events[ev.eventAction] = ev.eventDate;
  }

  const statuses = Array.isArray(rdap.status) ? rdap.status : [];

  // Nameservers come as objects with an ldhName.
  const nameservers = (rdap.nameservers || [])
    .map((ns) => (ns.ldhName || "").toLowerCase())
    .filter(Boolean);

  // Registrar lives in the entities list, role "registrar".
  let registrar = null;
  for (const ent of rdap.entities || []) {
    const roles = ent.roles || [];
    if (roles.includes("registrar")) {
      registrar = vcardField(ent, "fn") || ent.handle || null;
      break;
    }
  }

  return {
    domain: rdap.ldhName || null,
    registrar,
    statuses,
    nameservers,
    created: events.registration || null,
    updated: events.lastChanged || null,
    expires: events.expiration || null,
    dnssec: rdap.secureDNS ? Boolean(rdap.secureDNS.delegationSigned) : null,
  };
}

// Pull a named property out of an RDAP jCard (vcardArray) structure.
function vcardField(entity, field) {
  const vcard = entity.vcardArray && entity.vcardArray[1];
  if (!Array.isArray(vcard)) return null;
  const row = vcard.find((r) => r[0] === field);
  return row ? row[3] : null;
}

export async function lookupDomain(domain) {
  const res = await fetch(RDAP_BOOTSTRAP + encodeURIComponent(domain), {
    headers: { accept: "application/rdap+json" },
    redirect: "follow",
  });
  if (res.status === 404) {
    throw new Error(`No RDAP record for "${domain}" (registry may not support RDAP)`);
  }
  if (!res.ok) {
    throw new Error(`RDAP lookup failed (HTTP ${res.status})`);
  }
  const data = await res.json();
  return normalize(data);
}
