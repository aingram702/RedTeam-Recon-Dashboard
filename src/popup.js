// Popup controller: kicks off a recon pass for the active tab and renders each
// panel as its result streams back from the service worker.

const $ = (sel, root = document) => root.querySelector(sel);
const panelEl = (name) => $(`.panel[data-panel="${name}"]`);

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function setStatus(name, state, label) {
  const p = panelEl(name);
  if (!p) return;
  const s = p.querySelector("[data-status]");
  s.className = `status ${state}`;
  s.textContent = label;
}

function setBody(name, html) {
  const p = panelEl(name);
  if (p) p.querySelector("[data-body]").innerHTML = html;
}

// ---- Renderers -------------------------------------------------------------

function renderMeta(ok, data, error) {
  const t = $("#target");
  if (!ok) {
    t.textContent = error || "No inspectable tab.";
    for (const n of ["tech", "whois", "dns", "ports"]) {
      setStatus(n, "err", "n/a");
      setBody(n, `<div class="error-msg">${esc(error || "Unavailable")}</div>`);
    }
    return;
  }
  t.innerHTML = `${esc(data.hostname)} <span class="dom">&middot; ${esc(data.domain)}</span>`;
}

function renderTech(data) {
  const techs = data.technologies || [];
  if (techs.length === 0) {
    setStatus("tech", "ok", "none");
    setBody("tech", `<div class="empty">No technologies fingerprinted.</div>`);
    return;
  }
  setStatus("tech", "ok", `${techs.length} found`);

  const byCat = {};
  for (const t of techs) (byCat[t.category] ||= []).push(t);

  const order = ["CMS", "Framework", "JS Library", "Analytics", "Tag Manager",
    "CDN", "Web Server", "Language", "Security", "Ecommerce"];
  const cats = Object.keys(byCat).sort((a, b) => {
    const ia = order.indexOf(a), ib = order.indexOf(b);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });

  let html = "";
  for (const cat of cats) {
    html += `<div class="tech-group"><h3>${esc(cat)}</h3><div class="chips">`;
    for (const t of byCat[cat]) {
      html += `<span class="chip" title="${esc(t.evidence.join(", "))}">${esc(t.name)}</span>`;
    }
    html += `</div></div>`;
  }
  setBody("tech", html);
}

function renderWhois(d) {
  setStatus("whois", "ok", "ok");
  const fmt = (v) => (v ? esc(v) : "&mdash;");
  const date = (v) => (v ? esc(String(v).replace("T", " ").replace(/\.\d+Z?$/, "").replace("Z", " UTC")) : "&mdash;");
  const rows = [
    ["Domain", fmt(d.domain)],
    ["Registrar", fmt(d.registrar)],
    ["Created", date(d.created)],
    ["Updated", date(d.updated)],
    ["Expires", date(d.expires)],
    ["DNSSEC", d.dnssec == null ? "&mdash;" : d.dnssec ? "signed" : "unsigned"],
  ];
  let html = `<dl class="kv">`;
  for (const [k, v] of rows) html += `<dt>${k}</dt><dd>${v}</dd>`;
  html += `</dl>`;

  if (d.statuses && d.statuses.length) {
    html += `<div class="section-label">Status</div><div class="chips">`;
    for (const s of d.statuses) html += `<span class="chip">${esc(s)}</span>`;
    html += `</div>`;
  }
  if (d.nameservers && d.nameservers.length) {
    html += `<div class="section-label">Nameservers</div><div class="mono-list">`;
    for (const ns of d.nameservers) html += `<div>${esc(ns)}</div>`;
    html += `</div>`;
  }
  setBody("whois", html);
}

function renderDns(records) {
  const order = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"];
  let total = 0;
  let html = "";
  for (const type of order) {
    const recs = records[type];
    if (!recs || recs.error || recs.length === 0) continue;
    total += recs.length;
    html += `<div class="dns-type"><h3>${esc(type)}</h3>`;
    for (const r of recs) {
      html += `<div class="dns-rec">${esc(r.value)}<span class="ttl">  ttl=${esc(r.ttl)}</span></div>`;
    }
    html += `</div>`;
  }
  if (total === 0) {
    setStatus("dns", "ok", "none");
    setBody("dns", `<div class="empty">No DNS records returned.</div>`);
    return;
  }
  setStatus("dns", "ok", `${total} records`);
  setBody("dns", html);
}

function renderPorts(d) {
  if (!d.seen) {
    setStatus("ports", "ok", "no data");
    setBody("ports", `<div class="empty">Host <span class="mono-list" style="display:inline">${esc(d.ip)}</span> not in Shodan InternetDB &mdash; no exposed surface on record.</div>`);
    return;
  }
  const n = d.ports.length;
  setStatus("ports", n ? "ok" : "ok", n ? `${n} ports` : "0 ports");

  let html = `<dl class="kv"><dt>IP</dt><dd>${esc(d.ip)}</dd></dl>`;

  if (n) {
    html += `<div class="section-label">Open ports</div><div class="ports-grid">`;
    for (const p of d.ports) {
      const svc = p.service ? ` <span class="cat">${esc(p.service)}</span>` : "";
      html += `<span class="chip port">${esc(p.port)}${svc}</span>`;
    }
    html += `</div>`;
  } else {
    html += `<div class="empty">No open ports on record.</div>`;
  }

  if (d.vulns && d.vulns.length) {
    html += `<div class="section-label">Known CVEs (${d.vulns.length})</div><div class="chips">`;
    for (const v of d.vulns.slice(0, 30)) html += `<span class="chip vuln">${esc(v)}</span>`;
    html += `</div>`;
  }
  if (d.cpes && d.cpes.length) {
    html += `<div class="section-label">Detected products</div><div class="mono-list">`;
    for (const c of d.cpes.slice(0, 20)) html += `<div>${esc(c)}</div>`;
    html += `</div>`;
  }
  if (d.tags && d.tags.length) {
    html += `<div class="section-label">Tags</div><div class="chips">`;
    for (const t of d.tags) html += `<span class="chip">${esc(t)}</span>`;
    html += `</div>`;
  }
  setBody("ports", html);
}

// ---- Wiring ----------------------------------------------------------------

function handlePanel(msg) {
  const { panel, ok, data, error } = msg;
  if (panel === "meta") return renderMeta(ok, data, error);

  if (!ok) {
    setStatus(panel, "err", "error");
    setBody(panel, `<div class="error-msg">${esc(error || "Lookup failed")}</div>`);
    return;
  }
  switch (panel) {
    case "tech": return renderTech(data);
    case "whois": return renderWhois(data);
    case "dns": return renderDns(data);
    case "ports": return renderPorts(data);
  }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === "recon:panel") handlePanel(msg);
});

function resetPanels() {
  for (const n of ["tech", "whois", "dns", "ports"]) {
    setStatus(n, "loading", "running");
  }
  setBody("tech", `<div class="placeholder">Fingerprinting page&hellip;</div>`);
  setBody("whois", `<div class="placeholder">Querying registry&hellip;</div>`);
  setBody("dns", `<div class="placeholder">Resolving records&hellip;</div>`);
  setBody("ports", `<div class="placeholder">Checking Shodan InternetDB&hellip;</div>`);
}

async function start() {
  resetPanels();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    renderMeta(false, null, "No active tab found.");
    return;
  }
  chrome.runtime.sendMessage({ type: "recon:start", tab: { id: tab.id, url: tab.url } });
}

$("#rescan").addEventListener("click", start);
start();
