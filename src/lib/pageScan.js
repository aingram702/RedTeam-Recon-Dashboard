// Runs inside the inspected page (injected via chrome.scripting.executeScript
// in the MAIN world). MUST be fully self-contained -- it is serialized with
// Function.prototype.toString(), so it cannot reference anything from the
// surrounding module scope.
//
// Gathers the raw signal bundle the fingerprint matcher consumes. Header
// collection uses a same-origin fetch of the current document, which is
// allowed to read every response header except Set-Cookie -- so no broad
// host permission for arbitrary sites is required.
export async function pageScan() {
  const HEADERS_OF_INTEREST = [
    "server", "x-powered-by", "x-aspnet-version", "x-generator",
    "cf-ray", "x-amz-cf-id", "x-served-by", "x-akamai-transformed",
    "x-vercel-id", "x-nf-request-id", "x-wix-request-id",
    "strict-transport-security", "via", "x-cache",
  ];

  // JS globals: diff the window against a fresh iframe's window to isolate
  // page-added globals from the browser's built-ins.
  let globals = [];
  try {
    const probe = document.createElement("iframe");
    probe.style.display = "none";
    document.documentElement.appendChild(probe);
    const builtins = new Set(Object.getOwnPropertyNames(probe.contentWindow));
    document.documentElement.removeChild(probe);
    globals = Object.getOwnPropertyNames(window).filter((k) => !builtins.has(k));
  } catch (e) {
    globals = [];
  }

  const scripts = Array.from(document.scripts)
    .map((s) => s.src)
    .filter(Boolean);
  Array.from(document.querySelectorAll('link[href]')).forEach((l) => scripts.push(l.href));

  const cookies = document.cookie
    .split(";")
    .map((c) => c.split("=")[0].trim())
    .filter(Boolean);

  const metaEl = document.querySelector('meta[name="generator"]');
  const metaGenerator = metaEl ? metaEl.getAttribute("content") || "" : "";

  // A bounded slice of markup for HTML-pattern signatures.
  const html = document.documentElement.outerHTML.slice(0, 200000);

  const headers = {};
  try {
    const res = await fetch(location.href, { method: "GET", credentials: "include" });
    for (const name of HEADERS_OF_INTEREST) {
      const v = res.headers.get(name);
      if (v) headers[name] = v;
    }
  } catch (e) {
    // Cross-origin redirects or CSP can block this; headers stay partial.
  }

  return { globals, scripts, cookies, metaGenerator, html, headers };
}
