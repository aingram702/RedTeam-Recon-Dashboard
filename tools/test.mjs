// Unit tests for the recon libraries. Network is stubbed with canned payloads
// shaped like the real RDAP / DoH / InternetDB responses, so parsing logic is
// exercised without live egress. Run: node tools/test.mjs
import assert from "node:assert";

import { registrableDomain, isScannableHost, isPublicIPv4 } from "../src/lib/domain.js";
import { detect } from "../src/lib/fingerprints.js";
import { serviceName } from "../src/lib/ports.js";

let pass = 0;
function test(name, fn) {
  try {
    fn();
    pass++;
    console.log(`  ok   ${name}`);
  } catch (e) {
    console.error(`  FAIL ${name}\n       ${e.message}`);
    process.exitCode = 1;
  }
}
async function atest(name, fn) {
  try {
    await fn();
    pass++;
    console.log(`  ok   ${name}`);
  } catch (e) {
    console.error(`  FAIL ${name}\n       ${e.message}`);
    process.exitCode = 1;
  }
}

// Install a fetch stub that routes by URL substring to a canned response.
function stubFetch(routes) {
  globalThis.fetch = async (url) => {
    for (const [needle, resp] of routes) {
      if (String(url).includes(needle)) {
        return {
          ok: resp.status ? resp.status < 400 : true,
          status: resp.status || 200,
          json: async () => resp.body,
        };
      }
    }
    throw new Error(`no stub route for ${url}`);
  };
}

console.log("domain helpers");
test("registrableDomain: simple", () =>
  assert.equal(registrableDomain("www.example.com"), "example.com"));
test("registrableDomain: apex", () =>
  assert.equal(registrableDomain("example.com"), "example.com"));
test("registrableDomain: deep subdomain", () =>
  assert.equal(registrableDomain("a.b.c.example.com"), "example.com"));
test("registrableDomain: two-label TLD", () =>
  assert.equal(registrableDomain("shop.example.co.uk"), "example.co.uk"));
test("isScannableHost: rejects localhost", () =>
  assert.equal(isScannableHost("localhost"), false));
test("isScannableHost: rejects single label", () =>
  assert.equal(isScannableHost("intranet"), false));
test("isScannableHost: accepts domain", () =>
  assert.equal(isScannableHost("example.com"), true));
test("isScannableHost: accepts public bare IP", () =>
  assert.equal(isScannableHost("93.184.216.34"), true));
test("isScannableHost: rejects private IP (leak guard)", () =>
  assert.equal(isScannableHost("192.168.1.1"), false));
test("isScannableHost: rejects loopback IP", () =>
  assert.equal(isScannableHost("127.0.0.1"), false));
test("isScannableHost: rejects internal TLD", () =>
  assert.equal(isScannableHost("intranet.corp"), false));
test("isScannableHost: rejects .local", () =>
  assert.equal(isScannableHost("printer.local"), false));

console.log("isPublicIPv4 (leak guard)");
test("public IP", () => assert.equal(isPublicIPv4("8.8.8.8"), true));
test("RFC1918 10/8", () => assert.equal(isPublicIPv4("10.1.2.3"), false));
test("RFC1918 172.16/12", () => assert.equal(isPublicIPv4("172.20.5.5"), false));
test("RFC1918 192.168/16", () => assert.equal(isPublicIPv4("192.168.0.1"), false));
test("CGNAT 100.64/10", () => assert.equal(isPublicIPv4("100.64.0.1"), false));
test("link-local 169.254", () => assert.equal(isPublicIPv4("169.254.1.1"), false));
test("loopback 127/8", () => assert.equal(isPublicIPv4("127.0.0.1"), false));
test("multicast 224+", () => assert.equal(isPublicIPv4("239.255.0.1"), false));
test("octet overflow rejected", () => assert.equal(isPublicIPv4("999.1.1.1"), false));
test("non-IP rejected", () => assert.equal(isPublicIPv4("example.com"), false));

console.log("ports.serviceName");
test("well-known port maps", () => assert.equal(serviceName(443), "HTTPS"));
test("unknown port is null", () => assert.equal(serviceName(12345), null));

console.log("fingerprint matcher");
test("detects WordPress + nginx + Cloudflare + jQuery", () => {
  const found = detect({
    globals: ["jQuery", "wp"],
    scripts: ["https://site/wp-includes/js/jquery.min.js"],
    cookies: ["PHPSESSID"],
    metaGenerator: "WordPress 6.5.2",
    html: '<html><body class="home"></body></html>',
    headers: { server: "nginx/1.24.0", "cf-ray": "abc123", "x-powered-by": "PHP/8.2" },
  });
  const names = found.map((t) => t.name);
  for (const want of ["WordPress", "jQuery", "nginx", "Cloudflare", "PHP"]) {
    assert.ok(names.includes(want), `expected ${want} in ${names.join(",")}`);
  }
});
test("detects Next.js/React SPA", () => {
  const found = detect({
    globals: ["__NEXT_DATA__", "React"],
    scripts: ["https://site/_next/static/chunks/main.js"],
    cookies: [],
    metaGenerator: "",
    html: '<div id="__next"></div>',
    headers: { "x-vercel-id": "iad1::xyz", "x-powered-by": "Next.js" },
  });
  const names = found.map((t) => t.name);
  assert.ok(names.includes("Next.js"));
  assert.ok(names.includes("React"));
  assert.ok(names.includes("Vercel"));
});
test("empty signals -> no detections", () => {
  assert.deepEqual(detect({}), []);
});
test("evidence is recorded", () => {
  const [wp] = detect({ metaGenerator: "WordPress 6.5" });
  assert.ok(wp.evidence.includes("meta generator"));
});

console.log("rdap parser (stubbed)");
await atest("normalizes a domain record", async () => {
  stubFetch([
    ["rdap.org/domain/example.com", {
      body: {
        ldhName: "EXAMPLE.COM",
        status: ["client delete prohibited", "client transfer prohibited"],
        secureDNS: { delegationSigned: true },
        nameservers: [{ ldhName: "A.IANA-SERVERS.NET" }, { ldhName: "B.IANA-SERVERS.NET" }],
        events: [
          { eventAction: "registration", eventDate: "1995-08-14T04:00:00Z" },
          { eventAction: "expiration", eventDate: "2026-08-13T04:00:00Z" },
          { eventAction: "last changed", eventDate: "2025-08-14T07:01:44Z" },
        ],
        entities: [
          { roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]] },
        ],
      },
    }],
  ]);
  const { lookupDomain } = await import("../src/lib/rdap.js");
  const d = await lookupDomain("example.com");
  assert.equal(d.domain, "EXAMPLE.COM");
  assert.equal(d.registrar, "RESERVED-Internet Assigned Numbers Authority");
  assert.equal(d.dnssec, true);
  assert.equal(d.created, "1995-08-14T04:00:00Z");
  assert.equal(d.expires, "2026-08-13T04:00:00Z");
  assert.deepEqual(d.nameservers, ["a.iana-servers.net", "b.iana-servers.net"]);
  assert.equal(d.statuses.length, 2);
});
await atest("maps 404 to a friendly error", async () => {
  stubFetch([["rdap.org/domain/", { status: 404, body: {} }]]);
  const { lookupDomain } = await import("../src/lib/rdap.js");
  await assert.rejects(() => lookupDomain("nope.invalid"), /No RDAP record/);
});

console.log("dns parser (stubbed)");
await atest("parses A and NS answers, isolates per-type errors", async () => {
  stubFetch([
    ["type=A", { body: { Answer: [{ name: "example.com", type: 1, TTL: 300, data: "93.184.216.34" }] } }],
    ["type=NS", { body: { Answer: [{ name: "example.com", type: 2, TTL: 3600, data: "a.iana-servers.net." }] } }],
    ["type=", { status: 500, body: {} }], // everything else fails
  ]);
  const { lookupAll, resolveIPv4 } = await import("../src/lib/dns.js");
  const recs = await lookupAll("example.com");
  assert.equal(recs.A[0].value, "93.184.216.34");
  assert.equal(recs.A[0].type, "A");
  assert.equal(recs.NS[0].value, "a.iana-servers.net.");
  assert.ok(recs.MX.error, "MX should carry an error object");
  const ip = await resolveIPv4("example.com");
  assert.equal(ip, "93.184.216.34");
});

console.log("ports parser (stubbed)");
await atest("parses InternetDB hit", async () => {
  stubFetch([
    ["internetdb.shodan.io/93.184", {
      body: {
        ip: "93.184.216.34",
        ports: [443, 80, 22],
        hostnames: ["example.com"],
        cpes: ["cpe:/a:nginx:nginx"],
        tags: ["cdn"],
        vulns: ["CVE-2021-12345"],
      },
    }],
  ]);
  const { lookupIP } = await import("../src/lib/ports.js");
  const d = await lookupIP("93.184.216.34");
  assert.equal(d.seen, true);
  assert.deepEqual(d.ports.map((p) => p.port), [22, 80, 443]); // sorted
  assert.equal(d.ports.find((p) => p.port === 443).service, "HTTPS");
  assert.deepEqual(d.vulns, ["CVE-2021-12345"]);
});
await atest("treats 404 as no-surface, not error", async () => {
  stubFetch([["internetdb.shodan.io/", { status: 404, body: {} }]]);
  const { lookupIP } = await import("../src/lib/ports.js");
  const d = await lookupIP("10.0.0.1");
  assert.equal(d.seen, false);
  assert.deepEqual(d.ports, []);
});

console.log(`\n${pass} checks passed`);
