// Service worker: orchestrates a recon pass and streams each panel's result
// back to the popup as soon as it lands, so slow lookups never block fast ones.

import { lookupAll, resolveIPv4 } from "./lib/dns.js";
import { lookupDomain } from "./lib/rdap.js";
import { lookupIP } from "./lib/ports.js";
import { detect } from "./lib/fingerprints.js";
import { pageScan } from "./lib/pageScan.js";
import { registrableDomain, isScannableHost } from "./lib/domain.js";

// Message the popup directly (popup listens on runtime messages).
function emit(panel, payload) {
  chrome.runtime.sendMessage({ type: "recon:panel", panel, ...payload }).catch(() => {});
}

async function panel(name, fn) {
  try {
    const data = await fn();
    emit(name, { ok: true, data });
    return data;
  } catch (err) {
    emit(name, { ok: false, error: err.message });
    return null;
  }
}

async function runRecon(tab) {
  let url;
  try {
    url = new URL(tab.url);
  } catch {
    emit("meta", { ok: false, error: "This tab has no inspectable URL." });
    return;
  }

  if (!/^https?:$/.test(url.protocol)) {
    emit("meta", { ok: false, error: `Cannot recon a ${url.protocol} page. Open an http(s) site.` });
    return;
  }

  const hostname = url.hostname;
  if (!isScannableHost(hostname)) {
    emit("meta", { ok: false, error: `"${hostname}" is not a scannable public host.` });
    return;
  }

  const domain = registrableDomain(hostname);
  emit("meta", { ok: true, data: { hostname, domain, url: url.href } });

  // Tech fingerprint: inject the page scanner, then match signatures.
  panel("tech", async () => {
    const [inj] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: "MAIN",
      func: pageScan,
    });
    const signals = inj && inj.result ? inj.result : {};
    return { technologies: detect(signals), signalCount: (signals.globals || []).length };
  });

  // WHOIS / RDAP on the registrable domain.
  panel("whois", () => lookupDomain(domain));

  // DNS records for the exact hostname.
  const dnsPromise = panel("dns", () => lookupAll(hostname));

  // Exposed ports: resolve to an IP first, then query InternetDB.
  panel("ports", async () => {
    const ip = await resolveIPv4(hostname);
    if (!ip) throw new Error("Could not resolve an IPv4 address for this host.");
    return lookupIP(ip);
  });

  await dnsPromise;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "recon:start" && msg.tab) {
    runRecon(msg.tab);
    sendResponse({ started: true });
  }
  return false;
});
