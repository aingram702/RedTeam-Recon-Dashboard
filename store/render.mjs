// Renders all Chrome Web Store graphical assets (promo tiles + screenshots) to
// exact pixel dimensions using the pre-installed Chromium via Playwright.
//
// The dashboard mock reuses the extension's real src/popup.css, so screenshots
// stay faithful to the shipped UI. Run: node store/render.mjs
import { createRequire } from "module";
import { readFileSync, mkdirSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const require = createRequire(import.meta.url);
const { chromium } = require("/opt/node22/lib/node_modules/playwright");

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const OUT = join(__dirname, "assets");
mkdirSync(OUT, { recursive: true });

const POPUP_CSS = readFileSync(join(ROOT, "src", "popup.css"), "utf8");

// Brand tokens shared by the marketing frame around the mock.
const BRAND = `
  --bg:#0d1117; --panel:#161b22; --border:#2a3140; --text:#e6edf3;
  --muted:#8b98a9; --accent:#ff4d4d;
`;

// --- Populated dashboard panels (mirrors what popup.js renders) -------------

const P = {
  head: (title, status, cls = "ok") =>
    `<div class="panel-head"><h2>${title}</h2><span class="status ${cls}">${status}</span></div>`,

  tech: `<section class="panel" data-panel="tech">
    ${p("Technology Stack", "11 found")}
    <div class="panel-body">
      <div class="tech-group"><h3>CMS</h3><div class="chips"><span class="chip">WordPress</span></div></div>
      <div class="tech-group"><h3>Framework</h3><div class="chips"><span class="chip">Next.js</span><span class="chip">React</span></div></div>
      <div class="tech-group"><h3>JS Library</h3><div class="chips"><span class="chip">jQuery</span><span class="chip">Bootstrap</span></div></div>
      <div class="tech-group"><h3>Analytics</h3><div class="chips"><span class="chip">Google Analytics</span><span class="chip">Google Tag Manager</span></div></div>
      <div class="tech-group"><h3>CDN</h3><div class="chips"><span class="chip">Cloudflare</span></div></div>
      <div class="tech-group"><h3>Web Server</h3><div class="chips"><span class="chip">nginx</span></div></div>
      <div class="tech-group"><h3>Language</h3><div class="chips"><span class="chip">PHP</span></div></div>
    </div></section>`,

  whois: `<section class="panel" data-panel="whois">
    ${p("WHOIS &middot; RDAP", "ok")}
    <div class="panel-body">
      <dl class="kv">
        <dt>Domain</dt><dd>ACME-CORP.COM</dd>
        <dt>Registrar</dt><dd>MarkMonitor Inc.</dd>
        <dt>Created</dt><dd>2004-03-15 09:00 UTC</dd>
        <dt>Updated</dt><dd>2025-11-02 14:20 UTC</dd>
        <dt>Expires</dt><dd>2027-03-15 09:00 UTC</dd>
        <dt>DNSSEC</dt><dd>signed</dd>
      </dl>
      <div class="section-label">Status</div>
      <div class="chips"><span class="chip">client transfer prohibited</span><span class="chip">client delete prohibited</span></div>
      <div class="section-label">Nameservers</div>
      <div class="mono-list"><div>ada.ns.cloudflare.com</div><div>rob.ns.cloudflare.com</div></div>
    </div></section>`,

  dns: `<section class="panel" data-panel="dns">
    ${p("DNS Records", "9 records")}
    <div class="panel-body">
      <div class="dns-type"><h3>A</h3><div class="dns-rec">104.18.12.34<span class="ttl">  ttl=300</span></div><div class="dns-rec">104.18.13.34<span class="ttl">  ttl=300</span></div></div>
      <div class="dns-type"><h3>AAAA</h3><div class="dns-rec">2606:4700::6812:c22<span class="ttl">  ttl=300</span></div></div>
      <div class="dns-type"><h3>MX</h3><div class="dns-rec">10 aspmx.l.google.com.<span class="ttl">  ttl=3600</span></div></div>
      <div class="dns-type"><h3>NS</h3><div class="dns-rec">ada.ns.cloudflare.com.<span class="ttl">  ttl=86400</span></div></div>
      <div class="dns-type"><h3>TXT</h3><div class="dns-rec">"v=spf1 include:_spf.google.com ~all"<span class="ttl">  ttl=3600</span></div></div>
    </div></section>`,

  ports: `<section class="panel" data-panel="ports">
    ${p("Exposed Ports &amp; Surface", "3 ports")}
    <div class="panel-body">
      <dl class="kv"><dt>IP</dt><dd>104.18.12.34</dd></dl>
      <div class="section-label">Open ports</div>
      <div class="ports-grid">
        <span class="chip port">80 <span class="cat">HTTP</span></span>
        <span class="chip port">443 <span class="cat">HTTPS</span></span>
        <span class="chip port">8080 <span class="cat">HTTP-alt</span></span>
      </div>
      <div class="section-label">Known CVEs (2)</div>
      <div class="chips"><span class="chip vuln">CVE-2023-44487</span><span class="chip vuln">CVE-2024-27316</span></div>
      <div class="section-label">Detected products</div>
      <div class="mono-list"><div>cpe:/a:nginx:nginx:1.24.0</div><div>cpe:/a:openssl:openssl:3.0.2</div></div>
      <div class="section-label">Tags</div>
      <div class="chips"><span class="chip">cdn</span><span class="chip">cloud</span></div>
    </div></section>`,

  guard: `<section class="panel" data-panel="meta">
    ${p("Recon Status", "blocked", "err")}
    <div class="panel-body">
      <div class="error-msg">"10.0.4.17" is a private, internal, or reserved host &mdash; external recon skipped to avoid leaking internal network data.</div>
    </div></section>`,
};

function p(title, status) {
  const cls = status === "blocked" ? "err" : "ok";
  return `<div class="panel-head"><h2>${title}</h2><span class="status ${cls}">${status}</span></div>`;
}

function topbar(host, dom) {
  return `<header class="topbar">
    <div class="brand"><span class="brand-mark">&#9673;</span>
      <div class="brand-text"><h1>Recon Dashboard</h1>
        <div class="target">${host} <span class="dom">&middot; ${dom}</span></div></div></div>
    <button class="rescan">&#8635;</button>
  </header>`;
}

// A framed popup card: fake browser-popup chrome + the dashboard panels.
function popupCard(host, dom, panelsHtml) {
  return `<div class="device">
    <div class="chrome"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
      <span class="chrome-title">RedTeam Recon Dashboard</span></div>
    <div class="popup">${topbar(host, dom)}<main>${panelsHtml}</main>
      <footer class="disclaimer">Passive intelligence from public sources (RDAP, DoH, Shodan InternetDB). No active scanning is performed. Use only against assets you are authorized to assess.</footer>
    </div></div>`;
}

// --- Layout scaffolding -----------------------------------------------------

function pageShell(inner, extraCss = "") {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    :root{${BRAND}}
    ${POPUP_CSS}
    /* neutralize popup.css body sizing for the marketing canvas */
    html,body{width:auto;max-height:none;overflow:hidden;margin:0;}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--text);}
    .device{width:440px;border-radius:12px;overflow:hidden;border:1px solid var(--border);
      box-shadow:0 24px 60px rgba(0,0,0,.55);background:var(--bg);}
    .chrome{display:flex;align-items:center;gap:7px;padding:9px 12px;background:#0b0f16;border-bottom:1px solid var(--border);}
    .dot{width:11px;height:11px;border-radius:50%;display:inline-block;}
    .dot.r{background:#ff5f57}.dot.y{background:#febc2e}.dot.g{background:#28c840}
    .chrome-title{margin-left:8px;font-size:11px;color:var(--muted);font-family:var(--mono);}
    .popup{width:440px;}
    .popup main{padding:10px;display:flex;flex-direction:column;gap:10px;}
    .popup .topbar{position:static;}
    /* screenshot canvas */
    .canvas{width:1280px;height:800px;display:flex;align-items:center;gap:56px;
      padding:0 72px;box-sizing:border-box;
      background:radial-gradient(1200px 600px at 78% 12%, #17202e 0%, #0d1117 60%),
                 linear-gradient(160deg,#0b0f16,#0d1117);}
    .copy{flex:1;max-width:520px;}
    .eyebrow{display:inline-flex;align-items:center;gap:8px;font-family:var(--mono);
      font-size:13px;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:18px;}
    .eyebrow::before{content:"";width:26px;height:2px;background:var(--accent);display:inline-block;}
    .copy h2{font-size:46px;line-height:1.08;margin:0 0 18px;font-weight:750;letter-spacing:-.5px;}
    .copy h2 .hl{color:var(--accent);}
    .copy p{font-size:18px;line-height:1.5;color:var(--muted);margin:0 0 22px;}
    .flist{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:11px;}
    .flist li{display:flex;align-items:flex-start;gap:11px;font-size:15.5px;color:#c4cdd9;}
    .flist li b{color:var(--text);font-weight:600;}
    .tick{color:var(--accent);font-weight:800;flex:none;}
    .stage{flex:none;display:flex;justify-content:center;}
    ${extraCss}
  </style></head><body>${inner}</body></html>`;
}

function screenshot(eyebrow, h2Html, features, card) {
  return pageShell(`<div class="canvas">
    <div class="copy">
      <div class="eyebrow">${eyebrow}</div>
      <h2>${h2Html}</h2>
      <ul class="flist">${features.map((f) => `<li><span class="tick">&#10003;</span><span>${f}</span></li>`).join("")}</ul>
    </div>
    <div class="stage">${card}</div>
  </div>`);
}

// --- Asset definitions ------------------------------------------------------

const HOST = "shop.acme-corp.com", DOM = "acme-corp.com";

const ASSETS = [
  {
    name: "screenshot-1-overview", w: 1280, h: 800,
    html: screenshot(
      "One-click recon",
      `Every recon signal for a site,<br><span class="hl">in a single click</span>`,
      [
        "<b>WHOIS/RDAP, DNS, tech stack &amp; exposed ports</b> in one dashboard",
        "Panels <b>stream in live</b> — fast lookups render instantly",
        "<b>No API keys, no config</b> — free public data sources",
      ],
      popupCard(HOST, DOM, P.tech + P.whois)
    ),
  },
  {
    name: "screenshot-2-whois-dns", w: 1280, h: 800,
    html: screenshot(
      "Ownership &amp; infrastructure",
      `WHOIS &amp; DNS,<br><span class="hl">at a glance</span>`,
      [
        "Registrar, key dates, status codes, <b>DNSSEC</b> &amp; nameservers",
        "<b>A, AAAA, CNAME, MX, NS, TXT, SOA, CAA</b> records",
        "Powered by <b>RDAP</b> and <b>DNS-over-HTTPS</b>",
      ],
      popupCard(HOST, DOM, P.whois + P.dns)
    ),
  },
  {
    name: "screenshot-3-ports", w: 1280, h: 800,
    html: screenshot(
      "Attack surface",
      `See the <span class="hl">exposed surface</span>`,
      [
        "<b>Open ports</b> with service labels for the resolved IP",
        "<b>Known CVEs</b>, detected products (CPEs) &amp; tags",
        "<b>Passive</b> data from Shodan InternetDB — nothing is scanned",
      ],
      popupCard(HOST, DOM, P.ports)
    ),
  },
  {
    name: "screenshot-4-tech", w: 1280, h: 800,
    html: screenshot(
      "Technology fingerprint",
      `Know the <span class="hl">full stack</span>`,
      [
        "CMS, frameworks, JS libraries, analytics &amp; tag managers",
        "CDN, web server &amp; server-side language",
        "Detected locally from page signals &amp; response headers",
      ],
      popupCard(HOST, DOM, P.tech)
    ),
  },
  {
    name: "screenshot-5-privacy", w: 1280, h: 800,
    html: screenshot(
      "Safe by default",
      `Private targets <span class="hl">stay private</span>`,
      [
        "<b>Refuses</b> private, loopback &amp; reserved hosts (10.x, 192.168.x, *.local)",
        "Split-horizon IPs are <b>never sent</b> to third parties",
        "Reads cookie <b>names only</b> · <b>activeTab</b> scope · explicit CSP",
      ],
      popupCard("10.0.4.17", "internal", P.guard)
    ),
  },
  // Small promo tile 440x280
  {
    name: "promo-small-440x280", w: 440, h: 280,
    html: pageShell(`<div class="tile small"><div class="mark">&#9673;</div>
      <div class="tname">RedTeam Recon Dashboard</div>
      <div class="ttag">WHOIS · DNS · Tech Stack · Exposed Ports</div>
      <div class="tsub">Passive recon for the current site — one click.</div></div>`,
      `.tile.small{width:440px;height:280px;box-sizing:border-box;padding:34px 32px;
        display:flex;flex-direction:column;justify-content:center;
        background:radial-gradient(600px 300px at 82% 8%, #1b2534 0%, #0d1117 62%),linear-gradient(160deg,#0b0f16,#0d1117);}
      .tile .mark{font-size:40px;color:var(--accent);line-height:1;margin-bottom:14px;
        text-shadow:0 0 22px rgba(255,77,77,.55);}
      .tile .tname{font-size:26px;font-weight:750;letter-spacing:-.3px;}
      .tile .ttag{margin-top:10px;font-family:var(--mono);font-size:12.5px;letter-spacing:1px;color:var(--accent);}
      .tile .tsub{margin-top:8px;font-size:14px;color:var(--muted);}`)
  },
  // Marquee promo tile 1400x560
  {
    name: "promo-marquee-1400x560", w: 1400, h: 560,
    html: pageShell(`<div class="marquee">
      <div class="mcopy"><div class="mmark">&#9673; <span>RedTeam Recon Dashboard</span></div>
        <h2>All the recon.<br><span class="hl">One click.</span></h2>
        <p>WHOIS/RDAP · DNS · technology fingerprint · exposed ports — aggregated for the site in your active tab. No keys, no config, nothing scanned.</p>
      </div>
      <div class="mstage">${popupCard(HOST, DOM, P.ports)}</div></div>`,
      `.marquee{width:1400px;height:560px;box-sizing:border-box;display:flex;align-items:center;gap:60px;
        padding:0 90px;overflow:hidden;
        background:radial-gradient(1000px 500px at 80% 6%, #18212f 0%, #0d1117 60%),linear-gradient(160deg,#0b0f16,#0d1117);}
      .mcopy{flex:1;}
      .mmark{display:flex;align-items:center;gap:10px;color:var(--accent);font-size:15px;
        font-family:var(--mono);letter-spacing:1px;margin-bottom:22px;}
      .mmark span{color:var(--text);}
      .mcopy h2{font-size:64px;line-height:1.02;margin:0 0 20px;font-weight:800;letter-spacing:-1px;}
      .mcopy h2 .hl{color:var(--accent);}
      .mcopy p{font-size:19px;line-height:1.55;color:var(--muted);max-width:600px;margin:0;}
      .mstage{flex:none;transform:translateY(6px);}`)
  },
];

// --- Render loop ------------------------------------------------------------

const browser = await chromium.launch({
  executablePath: "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
  args: ["--no-sandbox", "--force-color-profile=srgb"],
});

for (const a of ASSETS) {
  const page = await browser.newPage({
    viewport: { width: a.w, height: a.h },
    deviceScaleFactor: 1,
  });
  await page.setContent(a.html, { waitUntil: "networkidle" });

  // Auto-fit: if the mock card is taller than the canvas allows, scale its
  // stage down (vector transform keeps text crisp) so nothing is clipped.
  const dev = await page.$(".device");
  if (dev) {
    const bb = await dev.boundingBox();
    const margin = a.name.startsWith("promo-marquee") ? 48 : 96;
    const avail = a.h - margin;
    if (bb && bb.height > avail) {
      const scale = avail / bb.height;
      await page.evaluate((s) => {
        const st = document.querySelector(".stage, .mstage");
        st.style.transform = `scale(${s})`;
        st.style.transformOrigin = "center";
      }, scale);
    }
  }

  const path = join(OUT, `${a.name}.png`);
  await page.screenshot({ path, clip: { x: 0, y: 0, width: a.w, height: a.h } });
  console.log(`rendered ${a.name}.png (${a.w}x${a.h})`);
  await page.close();
}

await browser.close();
console.log("done");
