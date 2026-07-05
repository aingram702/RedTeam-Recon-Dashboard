// Technology fingerprint signatures + matcher.
//
// A signal bundle is gathered from two places: the live page (JS globals,
// <meta generator>, script/link URLs, cookie names, <html> markup) and the
// document's response headers (fetched separately). Each signature below is a
// small predicate over those signals. This is deliberately a compact,
// heuristic set -- not a full Wappalyzer clone -- covering the technologies
// most relevant to a recon pass.

// category order controls grouping in the UI.
export const CATEGORY_ORDER = [
  "CMS", "Framework", "JS Library", "Analytics", "CDN", "Web Server",
  "Language", "Security", "Ecommerce", "Tag Manager",
];

// Each signature: { name, category, and any of:
//   global:  RegExp|string tested against page JS global names
//   script:  RegExp tested against script/link src URLs
//   cookie:  RegExp tested against cookie names
//   meta:    RegExp tested against the <meta name=generator> content
//   html:    RegExp tested against a slice of the page HTML
//   header:  [headerName, RegExp] tested against a response header value
// }
const SIGNATURES = [
  // --- CMS ---
  { name: "WordPress", category: "CMS", meta: /WordPress/i, script: /\/wp-(content|includes)\//i },
  { name: "Drupal", category: "CMS", meta: /Drupal/i, header: ["x-generator", /Drupal/i] },
  { name: "Joomla", category: "CMS", meta: /Joomla/i },
  { name: "Ghost", category: "CMS", meta: /Ghost/i },
  { name: "Shopify", category: "Ecommerce", global: /^Shopify$/, script: /cdn\.shopify\.com/i },
  { name: "Wix", category: "CMS", header: ["x-wix-request-id", /.+/], script: /static\.wixstatic\.com/i },
  { name: "Squarespace", category: "CMS", html: /squarespace/i, header: ["x-served-by", /squarespace/i] },
  { name: "Webflow", category: "CMS", html: /data-wf-(page|site)/i, script: /website-files\.com/i },

  // --- Framework ---
  { name: "React", category: "Framework", global: /^(React|__REACT_DEVTOOLS_GLOBAL_HOOK__)$/, html: /data-reactroot|__NEXT_DATA__/i },
  { name: "Next.js", category: "Framework", global: /^__NEXT_DATA__$/, script: /\/_next\//i },
  { name: "Vue.js", category: "Framework", global: /^(Vue|__VUE__)$/, html: /data-v-[0-9a-f]{8}/i },
  { name: "Nuxt.js", category: "Framework", global: /^(__NUXT__|\$nuxt)$/, script: /\/_nuxt\//i },
  { name: "Angular", category: "Framework", global: /^(ng|getAllAngularRootElements)$/, html: /ng-version=|_nghost-/i },
  { name: "Svelte", category: "Framework", html: /svelte-[0-9a-z]{6}/i },
  { name: "Gatsby", category: "Framework", global: /^___gatsby$/, html: /id="___gatsby"/i },
  { name: "Ruby on Rails", category: "Framework", cookie: /^_.*_session$/, header: ["x-powered-by", /Phusion Passenger/i] },
  { name: "Laravel", category: "Framework", cookie: /^laravel_session$/i },
  { name: "Django", category: "Framework", cookie: /^(csrftoken|django)/i },
  { name: "ASP.NET", category: "Framework", cookie: /^ASP\.NET_SessionId$/i, header: ["x-aspnet-version", /.+/] },

  // --- JS Library ---
  { name: "jQuery", category: "JS Library", global: /^jQuery$/, script: /jquery(\.min)?\.js/i },
  { name: "Lodash", category: "JS Library", global: /^_$/ },
  { name: "Bootstrap", category: "JS Library", script: /bootstrap(\.min)?\.(js|css)/i },
  { name: "Tailwind CSS", category: "JS Library", html: /class="[^"]*\b(?:mx-auto|px-\d|py-\d|text-(?:sm|lg|xl)|bg-(?:white|gray|slate))\b/i },
  { name: "Moment.js", category: "JS Library", global: /^moment$/ },

  // --- Analytics ---
  { name: "Google Analytics", category: "Analytics", global: /^(ga|gtag|dataLayer)$/, script: /google-analytics\.com|googletagmanager\.com\/gtag/i },
  { name: "Google Tag Manager", category: "Tag Manager", script: /googletagmanager\.com\/gtm/i },
  { name: "Segment", category: "Analytics", global: /^analytics$/, script: /cdn\.segment\.com/i },
  { name: "Hotjar", category: "Analytics", global: /^hj$/, script: /static\.hotjar\.com/i },
  { name: "Mixpanel", category: "Analytics", global: /^mixpanel$/, script: /cdn\.mxpnl\.com/i },
  { name: "Plausible", category: "Analytics", script: /plausible\.io\/js/i },

  // --- CDN ---
  { name: "Cloudflare", category: "CDN", header: ["cf-ray", /.+/] },
  { name: "Amazon CloudFront", category: "CDN", header: ["x-amz-cf-id", /.+/] },
  { name: "Fastly", category: "CDN", header: ["x-served-by", /cache-.*-/i] },
  { name: "Akamai", category: "CDN", header: ["x-akamai-transformed", /.+/] },
  { name: "Vercel", category: "CDN", header: ["x-vercel-id", /.+/] },
  { name: "Netlify", category: "CDN", header: ["x-nf-request-id", /.+/] },

  // --- Web Server ---
  { name: "nginx", category: "Web Server", header: ["server", /nginx/i] },
  { name: "Apache", category: "Web Server", header: ["server", /apache/i] },
  { name: "Microsoft IIS", category: "Web Server", header: ["server", /IIS/i] },
  { name: "LiteSpeed", category: "Web Server", header: ["server", /LiteSpeed/i] },
  { name: "Caddy", category: "Web Server", header: ["server", /Caddy/i] },
  { name: "Envoy", category: "Web Server", header: ["server", /envoy/i] },

  // --- Language ---
  { name: "PHP", category: "Language", header: ["x-powered-by", /PHP/i], cookie: /^PHPSESSID$/ },
  { name: "Node.js / Express", category: "Language", header: ["x-powered-by", /Express/i] },
  { name: "ASP.NET (runtime)", category: "Language", header: ["x-powered-by", /ASP\.NET/i] },

  // --- Security ---
  { name: "reCAPTCHA", category: "Security", script: /google\.com\/recaptcha|gstatic\.com\/recaptcha/i },
  { name: "hCaptcha", category: "Security", script: /hcaptcha\.com/i },
  { name: "HSTS enabled", category: "Security", header: ["strict-transport-security", /.+/] },
];

function testHeader(headers, name, re) {
  const v = headers ? headers[name.toLowerCase()] : undefined;
  return typeof v === "string" && re.test(v);
}

function anyMatch(list, re) {
  return Array.isArray(list) && list.some((x) => re.test(x));
}

// Run every signature against a gathered signal bundle. Returns detections
// with the evidence that triggered them, de-duplicated by technology name.
export function detect(signals) {
  const { globals = [], scripts = [], cookies = [], metaGenerator = "", html = "", headers = {} } = signals;
  const found = new Map();

  for (const sig of SIGNATURES) {
    const evidence = [];

    if (sig.global && anyMatch(globals, sig.global)) evidence.push("JS global");
    if (sig.script && anyMatch(scripts, sig.script)) evidence.push("script URL");
    if (sig.cookie && anyMatch(cookies, sig.cookie)) evidence.push("cookie");
    if (sig.meta && metaGenerator && sig.meta.test(metaGenerator)) evidence.push("meta generator");
    if (sig.html && html && sig.html.test(html)) evidence.push("page markup");
    if (sig.header && testHeader(headers, sig.header[0], sig.header[1])) evidence.push(`${sig.header[0]} header`);

    if (evidence.length === 0) continue;

    const existing = found.get(sig.name);
    if (existing) {
      for (const e of evidence) if (!existing.evidence.includes(e)) existing.evidence.push(e);
    } else {
      found.set(sig.name, { name: sig.name, category: sig.category, evidence });
    }
  }

  return Array.from(found.values());
}
