// Caminhos públicos que normalmente existem em qualquer instalação WordPress.
// Nenhum deles exige autenticação: são arquivos e rotas expostos por padrão.
const CANDIDATE_PATHS = [
  { path: "/wp-json/", label: "REST API (wp-json)", severity: "info", risk: "Rota padrão da REST API." },
  { path: "/wp-json/wp/v2/users", label: "Usuários via REST API", severity: "critical", risk: "Pode expor nomes de usuários, facilitando ataques de força bruta.", checkUsers: true },
  { path: "/wp-json/wp/v2/posts", label: "Posts via REST API", severity: "info", risk: "Rota pública padrão de conteúdo." },
  { path: "/robots.txt", label: "robots.txt", severity: "info", risk: "Arquivo público padrão." },
  { path: "/wp-login.php", label: "Tela de login", severity: "info", risk: "Necessário, mas vale considerar limitar tentativas de login." },
  { path: "/wp-admin/", label: "Painel admin", severity: "info", risk: "Redireciona para login se não autenticado." },
  { path: "/xmlrpc.php", label: "XML-RPC", severity: "warning", risk: "Pode ser usado para brute force e ataques de amplificação." },
  { path: "/wp-content/", label: "wp-content", severity: "info", risk: "Diretório padrão de mídia e temas." },
  { path: "/wp-content/uploads/", label: "Uploads", severity: "info", risk: "Diretório de mídia.", checkListing: true },
  { path: "/wp-content/plugins/", label: "Plugins", severity: "info", risk: "Diretório de plugins.", checkListing: true },
  { path: "/wp-content/themes/", label: "Temas", severity: "info", risk: "Diretório de temas.", checkListing: true },
  { path: "/wp-cron.php", label: "wp-cron.php", severity: "info", risk: "Pode ser abusado para sobrecarregar o servidor se muito acessado." },
  { path: "/feed/", label: "Feed RSS", severity: "info", risk: "Recurso público padrão." },
  { path: "/comments/feed/", label: "Feed de comentários", severity: "info", risk: "Recurso público padrão." },
  { path: "/readme.html", label: "readme.html (versão do WP)", severity: "warning", risk: "Pode revelar a versão exata do WordPress instalada.", checkVersion: true },
  { path: "/license.txt", label: "license.txt", severity: "info", risk: "Arquivo padrão, baixo risco." }
];

// Caminhos padrão de sitemap testados como último fallback (menos confiável
// que robots.txt e a tag <link>, mas cobre sites que não declaram em lugar nenhum).
const SITEMAP_FALLBACK_PATHS = [
  { path: "/sitemap.xml", label: "sitemap.xml" },
  { path: "/sitemap_index.xml", label: "sitemap_index.xml" },
  { path: "/sitemap-index.xml", label: "sitemap-index.xml" },
  { path: "/wp-sitemap.xml", label: "wp-sitemap.xml" },
  { path: "/page-sitemap.xml", label: "page-sitemap.xml" },
  { path: "/post-sitemap.xml", label: "post-sitemap.xml" }
];

const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 };
const SEVERITY_LABEL = { critical: "🔴 Crítico", warning: "🟡 Atenção", info: "🟢 Info" };

const FETCH_TIMEOUT_MS = 6000;
const LINK_STATUS_CAP = 40;

// Sinais de tecnologia funcionam pra qualquer site, WordPress ou não.
// WordPress em si não entra aqui: já tem detecção própria (com fallback via /wp-json/).
const TECH_SIGNATURES = [
  // CMS / page builders
  { name: "Shopify", test: ({ html, headers }) => /cdn\.shopify\.com|Shopify\.theme/i.test(html || "") || /shopify/i.test(headers["x-shopid"] || headers["x-shardid"] || "") },
  { name: "Wix", test: ({ html }) => /static\.wixstatic\.com|Wix\.com Website Builder/i.test(html || "") },
  { name: "Squarespace", test: ({ html }) => /squarespace\.com|content="Squarespace/i.test(html || "") },
  { name: "Webflow", test: ({ html }) => /webflow\.com|content="Webflow"/i.test(html || "") },
  { name: "Drupal", test: ({ html, headers }) => /Drupal\.settings|content="Drupal/i.test(html || "") || /drupal/i.test(headers["x-generator"] || "") },
  { name: "Joomla", test: ({ html }) => /content="Joomla/i.test(html || "") },

  // Frameworks JS (detecção limitada: só HTML estático da home, sem executar JS)
  { name: "Next.js", test: ({ html }) => /__NEXT_DATA__|\/_next\/static/i.test(html || "") },
  { name: "Nuxt.js", test: ({ html }) => /__NUXT__/i.test(html || "") },
  { name: "Angular", test: ({ html }) => /ng-version=/i.test(html || "") },
  { name: "Vue.js", test: ({ html }) => /data-server-rendered="true"|cdn\.jsdelivr\.net\/npm\/vue|unpkg\.com\/vue/i.test(html || "") },

  // E-commerce
  { name: "WooCommerce", test: ({ html }) => /woocommerce/i.test(html || "") },
  { name: "PrestaShop", test: ({ html }) => /PrestaShop|\/modules\/ps_/i.test(html || "") },
  { name: "Magento", test: ({ html }) => /Mage\.Cookies|\/skin\/frontend\//i.test(html || "") },

  // CSS framework
  { name: "Bootstrap", test: ({ html }) => /bootstrap(\.min)?\.css|bootstrap\.bundle/i.test(html || "") },

  // CDN / hosting
  { name: "Cloudflare", test: ({ headers }) => !!headers["cf-ray"] || /cloudflare/i.test(headers["server"] || "") },
  { name: "Vercel", test: ({ headers }) => !!headers["x-vercel-id"] || /vercel/i.test(headers["server"] || "") },
  { name: "Netlify", test: ({ headers }) => !!headers["x-nf-request-id"] || /netlify/i.test(headers["server"] || "") },
  { name: "Fastly", test: ({ headers }) => !!headers["x-fastly-request-id"] || /fastly/i.test(headers["x-served-by"] || "") },
  { name: "Amazon CloudFront", test: ({ headers }) => !!headers["x-amz-cf-id"] || /cloudfront/i.test(headers["via"] || "") }
];

const SECURITY_HEADERS = [
  { key: "strict-transport-security", label: "Strict-Transport-Security (HSTS)" },
  { key: "content-security-policy", label: "Content-Security-Policy" },
  { key: "x-frame-options", label: "X-Frame-Options" }
];

const statusEl = document.getElementById("status");
const originEl = document.getElementById("site-origin");
const linksContainer = document.getElementById("links-container");
const linksList = document.getElementById("links-list");
const emptyState = document.getElementById("empty-state");
const rescanBtn = document.getElementById("rescan");
const domainToolsEl = document.getElementById("domain-tools");
const whoisLinkEl = document.getElementById("whois-link");
const defaultSitemapLinkEl = document.getElementById("default-sitemap-link");
const googleSiteLinkEl = document.getElementById("google-site-link");
const openAllBtn = document.getElementById("open-all-btn");
const trackersContainer = document.getElementById("trackers-container");
const trackersList = document.getElementById("trackers-list");
const sitemapContainer = document.getElementById("sitemap-container");
const sitemapList = document.getElementById("sitemap-list");
const sitemapEmpty = document.getElementById("sitemap-empty");
const openAllSitemapBtn = document.getElementById("open-all-sitemap-btn");
const copyReportBtn = document.getElementById("copy-report-btn");
const startInspectorBtn = document.getElementById("start-inspector-btn");
const techContainer = document.getElementById("tech-container");
const techList = document.getElementById("tech-list");
const securityContainer = document.getElementById("security-container");
const securityList = document.getElementById("security-list");
const tabsEl = document.getElementById("tabs");
const seoSummaryList = document.getElementById("seo-summary-list");
const seoHeadersList = document.getElementById("seo-headers-list");
const seoImagesSummary = document.getElementById("seo-images-summary");
const seoImagesIssuesList = document.getElementById("seo-images-issues-list");
const seoImagesOkList = document.getElementById("seo-images-ok-list");
const seoLinksList = document.getElementById("seo-links-list");
const seoSocialList = document.getElementById("seo-social-list");

let lastSitemapResults = [];

let lastFoundResults = [];

let lastTrackers = [];
let lastTechStack = [];
let lastSecurityChecks = [];
let lastIsWordPress = false;
let lastOrigin = "";
let lastSeoData = null;

function openInBackground(url) {
  // active: false mantém o foco no popup, então ele não fecha ao clicar.
  chrome.tabs.create({ url, active: false });
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

async function getActiveTabOrigin() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return null;
  try {
    const url = new URL(tab.url);
    if (!/^https?:$/.test(url.protocol)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

async function fetchHomepage(origin) {
  try {
    const res = await fetchWithTimeout(origin + "/");
    const headers = {};
    res.headers.forEach((value, key) => { headers[key] = value; });
    if (!res.ok) return { html: null, headers };
    return { html: await res.text(), headers };
  } catch {
    return { html: null, headers: {} };
  }
}

function detectTechStack(html, headers) {
  const matches = TECH_SIGNATURES
    .filter((s) => {
      try {
        return !!s.test({ html, headers });
      } catch {
        return false;
      }
    })
    .map((s) => s.name);

  // Header cru, além das assinaturas de CDN acima: útil pra saber se é
  // nginx, Apache, LiteSpeed etc., algo que nenhuma assinatura fixa cobre.
  if (headers["server"]) matches.push(`Servidor: ${headers["server"]}`);

  return matches;
}

// Testa se a versão http:// redireciona pra https://. Só faz sentido
// verificar quando o site já está sendo acessado via https.
async function checkHttpsForced(origin) {
  if (!origin.startsWith("https:")) return false;
  try {
    const res = await fetchWithTimeout(origin.replace("https:", "http:") + "/");
    return res.url.startsWith("https:");
  } catch {
    return false;
  }
}

function buildSecurityChecks(headers, httpsForced) {
  const checks = SECURITY_HEADERS.map((h) => ({
    label: h.label,
    ok: !!headers[h.key],
    note: headers[h.key] ? "Presente." : "Ausente, recomenda-se configurar."
  }));
  checks.push({
    label: "HTTPS forçado",
    ok: httpsForced,
    note: httpsForced ? "http:// redireciona para https://." : "http:// não redireciona para https://."
  });
  return checks;
}

async function detectWordPress(origin, homepageHtml) {
  const signals = ["wp-content", "wp-includes", "wp-json", "content=\"WordPress"];
  if (homepageHtml && signals.some((s) => homepageHtml.includes(s))) return true;

  // Fallback: confirma direto pela raiz da REST API.
  try {
    const res = await fetchWithTimeout(origin + "/wp-json/");
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (data && (data.name || data.namespaces)) return true;
    }
  } catch {
    // não é WP, ou está fora do ar
  }

  return false;
}

async function checkPath(origin, entry) {
  const url = origin + entry.path;
  try {
    const res = await fetchWithTimeout(url, { method: "GET" });
    const result = { ...entry, url, status: res.status, ok: res.ok };
    if (!res.ok) return result;

    if (entry.checkListing) {
      const text = await res.text();
      if (/index of \//i.test(text)) {
        result.severity = "critical";
        result.risk = "Listagem de diretório ativa: qualquer um pode navegar pelos arquivos.";
      }
    }

    if (entry.checkVersion) {
      const text = await res.text();
      const match = text.match(/version\s+([\d.]+)/i);
      if (match) {
        result.risk = `Versão do WordPress exposta: ${match[1]}.`;
      }
    }

    if (entry.checkUsers) {
      const data = await res.json().catch(() => null);
      if (Array.isArray(data) && data.length > 0) {
        const names = data.slice(0, 5).map((u) => u.slug || u.name).filter(Boolean);
        const suffix = data.length > names.length ? "..." : "";
        result.risk = `${data.length} usuário(s) expostos: ${names.join(", ")}${suffix}.`;
      } else {
        result.severity = "info";
        result.risk = "Rota responde, mas não expôs usuários.";
      }
    }

    return result;
  } catch {
    return { ...entry, url, status: null, ok: false };
  }
}

// O robots.txt é o jeito mais comum de achar o sitemap real de um site,
// porque é o próprio site que declara a URL exata nele.
async function getSitemapsFromRobots(origin) {
  try {
    const res = await fetchWithTimeout(origin + "/robots.txt");
    if (!res.ok) return [];
    const text = await res.text();
    const urls = [];
    for (const line of text.split(/\r?\n/)) {
      const match = line.match(/^\s*sitemap\s*:\s*(\S+)/i);
      if (match) urls.push(match[1].trim());
    }
    return [...new Set(urls)];
  } catch {
    return [];
  }
}

// Vários plugins de SEO (Rank Math, AIOSEO, etc.) só declaram o sitemap
// via <link rel="sitemap"> no <head>, sem escrever no robots.txt.
function getSitemapFromHtml(html, origin) {
  if (!html) return [];
  const match =
    html.match(/<link[^>]+rel=["']sitemap["'][^>]+href=["']([^"']+)["']/i) ||
    html.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["']sitemap["']/i);
  if (!match) return [];
  try {
    return [new URL(match[1], origin).toString()];
  } catch {
    return [];
  }
}

async function checkAbsoluteUrl(url, label) {
  try {
    const res = await fetchWithTimeout(url, { method: "GET" });
    return { label, url, status: res.status, ok: res.ok, severity: "info", risk: "Recurso padrão de SEO." };
  } catch {
    return { label, url, status: null, ok: false, severity: "info", risk: "Recurso padrão de SEO." };
  }
}

function dedupeByUrl(results) {
  const seen = new Set();
  return results.filter((r) => {
    if (seen.has(r.url)) return false;
    seen.add(r.url);
    return true;
  });
}

// Roda dentro da própria página (world: MAIN), pra ter acesso tanto ao DOM
// quanto às variáveis globais que scripts de rastreamento costumam expor.
function scanPageForTrackers() {
  const signatures = [
    { name: "Meta Pixel (Facebook/Instagram Ads)", test: () => !!window.fbq || !!document.querySelector('script[src*="connect.facebook.net"]') },
    { name: "Google Tag Manager", test: () => !!window.google_tag_manager || !!document.querySelector('script[src*="googletagmanager.com/gtm.js"]') },
    { name: "Google Analytics (GA4/Universal)", test: () => !!window.gtag || !!window.ga || !!document.querySelector('script[src*="google-analytics.com"]') },
    { name: "Google Ads / Remarketing", test: () => !!document.querySelector('script[src*="googleadservices.com"]') || !!document.querySelector('script[src*="googlesyndication.com"]') },
    { name: "TikTok Pixel", test: () => !!window.ttq || !!document.querySelector('script[src*="analytics.tiktok.com"]') },
    { name: "Pinterest Tag", test: () => !!window.pintrk || !!document.querySelector('script[src*="pinimg.com/ct"]') },
    { name: "Snapchat Pixel", test: () => !!window.snaptr || !!document.querySelector('script[src*="sc-static.net"]') },
    { name: "LinkedIn Insight Tag", test: () => !!window._linkedin_partner_id || !!document.querySelector('script[src*="snap.licdn.com"]') },
    { name: "Twitter/X Pixel", test: () => !!window.twq || !!document.querySelector('script[src*="static.ads-twitter.com"]') },
    { name: "Hotjar", test: () => !!window.hj || !!document.querySelector('script[src*="static.hotjar.com"]') },
    { name: "Microsoft Clarity", test: () => !!window.clarity || !!document.querySelector('script[src*="clarity.ms"]') },
    { name: "Jetpack Stats (WordPress.com)", test: () => !!document.querySelector('script[src*="pixel.wp.com"]') || !!document.querySelector('img[src*="pixel.wp.com"]') },
    { name: "HubSpot", test: () => !!document.querySelector('script[src*="js.hs-scripts.com"]') || !!document.querySelector('script[src*="js.hs-analytics.net"]') },
    { name: "Matomo/Piwik", test: () => !!window._paq },
    { name: "Google reCAPTCHA", test: () => !!document.querySelector('script[src*="recaptcha"]') },
    { name: "Criteo", test: () => !!document.querySelector('script[src*="criteo.com"]') },
    { name: "Taboola", test: () => !!document.querySelector('script[src*="taboola.com"]') },
    { name: "Outbrain", test: () => !!document.querySelector('script[src*="outbrain.com"]') }
  ];

  return signatures
    .filter((s) => {
      try {
        return !!s.test();
      } catch {
        return false;
      }
    })
    .map((s) => s.name);
}

// Roda dentro da própria página (world: MAIN), igual scanPageForTrackers,
// pra ler o DOM já renderizado (título, meta tags, headings, imagens, links reais).
function extractSeoData() {
  const getMeta = (name) => {
    const el = document.querySelector(`meta[name="${name}" i]`);
    return el ? el.getAttribute("content") : null;
  };

  const canonicalEl = document.querySelector('link[rel="canonical"]');

  const headings = Array.from(document.querySelectorAll("h1,h2,h3,h4,h5,h6")).map((el) => ({
    level: Number(el.tagName.slice(1)),
    text: el.textContent.trim().slice(0, 200)
  }));

  const images = Array.from(document.querySelectorAll("img")).map((img) => ({
    src: img.currentSrc || img.src || "",
    alt: img.getAttribute("alt"),
    title: img.getAttribute("title")
  }));

  const linkMap = new Map();
  document.querySelectorAll("a[href]").forEach((a) => {
    const href = a.href;
    const text = a.textContent.trim().slice(0, 120) || "(sem texto)";
    const key = href + "|" + text;
    if (linkMap.has(key)) {
      linkMap.get(key).count++;
    } else {
      linkMap.set(key, { href, text, count: 1 });
    }
  });

  const social = [];
  document.querySelectorAll('meta[property^="og:"]').forEach((el) => {
    social.push({ key: el.getAttribute("property"), value: el.getAttribute("content") });
  });
  document.querySelectorAll('meta[name^="twitter:"]').forEach((el) => {
    social.push({ key: el.getAttribute("name"), value: el.getAttribute("content") });
  });

  return {
    title: document.title || "",
    description: getMeta("description"),
    keywords: getMeta("keywords"),
    url: location.href,
    canonical: canonicalEl ? canonicalEl.href : null,
    robotsMeta: getMeta("robots"),
    author: getMeta("author"),
    publisher: getMeta("publisher"),
    lang: document.documentElement.lang || null,
    headings,
    images,
    links: Array.from(linkMap.values()),
    social
  };
}

// Testa status só dos links internos (mesmo origin), com teto de LINK_STATUS_CAP
// requisições únicas, pra não travar o popup em páginas com muitos links.
async function checkLinkStatuses(links, origin) {
  const internalHrefs = [...new Set(
    links
      .map((l) => l.href)
      .filter((href) => {
        try {
          return new URL(href).origin === origin;
        } catch {
          return false;
        }
      })
  )].slice(0, LINK_STATUS_CAP);

  const results = await Promise.all(
    internalHrefs.map(async (href) => {
      try {
        const res = await fetchWithTimeout(href, { method: "GET" });
        return [href, { status: res.status, ok: res.ok }];
      } catch {
        return [href, { status: null, ok: false }];
      }
    })
  );

  const statusMap = new Map(results);
  links.forEach((l) => {
    const s = statusMap.get(l.href);
    if (s) {
      l.status = s.status;
      l.statusOk = s.ok;
    }
  });
}

async function scanSeo() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) return null;
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: "MAIN",
      func: extractSeoData
    });
    return result || null;
  } catch {
    return null;
  }
}

// Injetado via chrome.scripting.executeScript (world isolado por padrão).
// Precisa ser 100% autocontido: nada de closures sobre variáveis externas,
// só APIs de DOM/CSSOM disponíveis em qualquer contexto de página.
function startElementInspector() {
  if (window.__sitexrayInspectorActive) return;
  window.__sitexrayInspectorActive = true;

  const COLORS = {
    bg: "#0a0e12",
    bgAlt: "#10161d",
    border: "#1e2a35",
    text: "#d6e4ec",
    textDim: "#6f8494",
    accent: "#39ff9e",
    cyan: "#2fe0ff",
    danger: "#ff4d5e"
  };
  const MONO = '"JetBrains Mono","Fira Code","SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace';

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    return Promise.resolve();
  }

  const highlight = document.createElement("div");
  highlight.id = "sitexray-highlight-box";
  Object.assign(highlight.style, {
    position: "fixed",
    pointerEvents: "none",
    zIndex: "2147483646",
    border: "2px solid " + COLORS.accent,
    background: "rgba(57,255,158,0.08)",
    borderRadius: "2px",
    display: "none"
  });
  document.documentElement.appendChild(highlight);

  const panelHost = document.createElement("div");
  panelHost.id = "sitexray-inspector-root";
  Object.assign(panelHost.style, {
    position: "fixed",
    left: "0",
    right: "0",
    bottom: "0",
    zIndex: "2147483647",
    height: "38vh",
    minHeight: "260px"
  });
  document.documentElement.appendChild(panelHost);

  const shadow = panelHost.attachShadow({ mode: "open" });
  const style = document.createElement("style");
  style.textContent =
    ":host{all:initial;}" +
    ".panel{font-family:" + MONO + ";background:" + COLORS.bg + ";color:" + COLORS.text + ";border-top:1px solid " + COLORS.border + ";height:100%;display:flex;flex-direction:column;box-shadow:0 -8px 24px rgba(0,0,0,0.5);box-sizing:border-box;}" +
    ".topbar{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 12px;border-bottom:1px solid " + COLORS.border + ";background:" + COLORS.bgAlt + ";}" +
    ".topbar strong{color:" + COLORS.accent + ";font-size:12px;white-space:nowrap;}" +
    ".hint{color:" + COLORS.textDim + ";font-size:10px;}" +
    ".close-btn{background:transparent;border:1px solid " + COLORS.border + ";color:" + COLORS.textDim + ";border-radius:4px;padding:3px 8px;cursor:pointer;font-family:" + MONO + ";font-size:10px;}" +
    ".close-btn:hover{border-color:" + COLORS.danger + ";color:" + COLORS.danger + ";}" +
    ".breadcrumb{padding:6px 12px;border-bottom:1px solid " + COLORS.border + ";font-size:10px;overflow-x:auto;white-space:nowrap;}" +
    ".crumb{color:" + COLORS.cyan + ";cursor:pointer;}" +
    ".crumb:hover{text-decoration:underline;}" +
    ".crumb-sep{color:" + COLORS.textDim + ";}" +
    ".body{flex:1;overflow-y:auto;padding:10px 12px;display:grid;grid-template-columns:1fr 1fr;gap:10px;box-sizing:border-box;}" +
    ".block{background:" + COLORS.bgAlt + ";border:1px solid " + COLORS.border + ";border-radius:4px;padding:8px;box-sizing:border-box;}" +
    ".block h4{margin:0 0 6px 0;font-size:9.5px;text-transform:uppercase;letter-spacing:.06em;color:" + COLORS.textDim + ";display:flex;justify-content:space-between;align-items:center;}" +
    ".copy-btn{background:transparent;border:1px solid " + COLORS.accent + ";color:" + COLORS.accent + ";border-radius:3px;padding:1px 6px;cursor:pointer;font-family:" + MONO + ";font-size:9px;}" +
    ".copy-btn:hover{background:" + COLORS.accent + ";color:#061109;}" +
    ".block pre{margin:0;white-space:pre-wrap;word-break:break-word;font-size:10px;line-height:1.5;color:" + COLORS.text + ";max-height:120px;overflow-y:auto;}" +
    ".block.full{grid-column:1 / -1;}" +
    ".list-item{cursor:pointer;color:" + COLORS.cyan + ";font-size:10.5px;padding:2px 0;}" +
    ".list-item:hover{text-decoration:underline;}" +
    ".empty{color:" + COLORS.textDim + ";font-size:10px;font-style:italic;}" +
    ".color-row{display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid " + COLORS.border + ";font-size:10px;}" +
    ".color-row:last-child{border-bottom:none;}" +
    ".swatch{width:16px;height:16px;border-radius:3px;border:1px solid rgba(255,255,255,0.25);flex-shrink:0;}" +
    ".color-label{color:" + COLORS.textDim + ";flex-shrink:0;min-width:110px;}" +
    ".color-value{flex:1;color:" + COLORS.text + ";word-break:break-all;}";
  shadow.appendChild(style);

  const panel = document.createElement("div");
  panel.className = "panel";
  panel.innerHTML =
    '<div class="topbar"><strong>SiteXray &gt; Element Info</strong><span class="hint">Passe o mouse e clique num elemento. Esc pra sair.</span><button class="close-btn" id="sx-close">Fechar</button></div>' +
    '<div class="breadcrumb" id="sx-breadcrumb"></div>' +
    '<div class="body" id="sx-body"><div class="empty" style="grid-column:1/-1;">Clique em um elemento da página pra ver os detalhes.</div></div>';
  shadow.appendChild(panel);

  function toHex(rgbStr) {
    const m = rgbStr && rgbStr.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const parts = m[1].split(",").map((s) => parseFloat(s.trim()));
    if (parts.slice(0, 3).some((n) => Number.isNaN(n))) return null;
    return "#" + parts.slice(0, 3).map((n) => Math.round(n).toString(16).padStart(2, "0")).join("");
  }

  function describeEl(el) {
    if (!el || el.nodeType !== 1) return "";
    let s = el.tagName.toLowerCase();
    if (el.id) s += "#" + el.id;
    if (el.classList.length) s += "." + Array.from(el.classList).slice(0, 3).join(".");
    return s;
  }

  function onMouseMove(e) {
    const path = e.composedPath ? e.composedPath() : [e.target];
    if (path.indexOf(panelHost) !== -1) {
      highlight.style.display = "none";
      return;
    }
    const el = document.elementFromPoint(e.clientX, e.clientY);
    if (!el) return;
    const rect = el.getBoundingClientRect();
    Object.assign(highlight.style, {
      display: "block",
      left: rect.left + "px",
      top: rect.top + "px",
      width: rect.width + "px",
      height: rect.height + "px"
    });
  }

  function renderInfo(el) {
    const rect = el.getBoundingClientRect();
    const cs = getComputedStyle(el);

    const chain = [];
    let cur = el;
    while (cur) {
      chain.unshift(cur);
      cur = cur.parentElement;
    }

    const breadcrumbEl = shadow.getElementById("sx-breadcrumb");
    breadcrumbEl.innerHTML = "";
    chain.forEach((node, i) => {
      if (i > 0) {
        const sep = document.createElement("span");
        sep.className = "crumb-sep";
        sep.textContent = " > ";
        breadcrumbEl.appendChild(sep);
      }
      const crumb = document.createElement("span");
      crumb.className = "crumb";
      crumb.textContent = describeEl(node) || node.tagName.toLowerCase();
      crumb.addEventListener("click", () => renderInfo(node));
      breadcrumbEl.appendChild(crumb);
    });

    const outerHtml = el.outerHTML.length > 1500 ? el.outerHTML.slice(0, 1500) + "\n..." : el.outerHTML;
    const layoutText = "height: " + Math.round(rect.height) + "px\nwidth: " + Math.round(rect.width) + "px";
    const positionText = "display: " + cs.display + "\nfloat: " + cs.float + "\nposition: " + cs.position;
    const textText = "font-family: " + cs.fontFamily + "\nfont-size: " + cs.fontSize + "\nline-height: " + cs.lineHeight;

    const bodyEl = shadow.getElementById("sx-body");
    bodyEl.innerHTML = "";

    [
      { title: "DOM", text: outerHtml, full: true },
      { title: "Layout", text: layoutText },
      { title: "Position", text: positionText },
      { title: "Text", text: textText }
    ].forEach((b) => {
      const block = document.createElement("div");
      block.className = "block" + (b.full ? " full" : "");

      const h4 = document.createElement("h4");
      h4.textContent = b.title;

      const copyBtn = document.createElement("button");
      copyBtn.className = "copy-btn";
      copyBtn.textContent = "Copiar";
      copyBtn.addEventListener("click", () => {
        copyText(b.text).then(() => {
          copyBtn.textContent = "Copiado!";
          setTimeout(() => { copyBtn.textContent = "Copiar"; }, 1200);
        });
      });
      h4.appendChild(copyBtn);

      const pre = document.createElement("pre");
      pre.textContent = b.text;

      block.appendChild(h4);
      block.appendChild(pre);
      bodyEl.appendChild(block);
    });

    const colorsBlock = document.createElement("div");
    colorsBlock.className = "block full";
    const colorsH4 = document.createElement("h4");
    colorsH4.textContent = "Colors";
    colorsBlock.appendChild(colorsH4);

    const colorEntries = [
      { label: "color", value: cs.color },
      { label: "background-color", value: cs.backgroundColor },
      { label: "border-color", value: cs.borderColor || cs.borderTopColor }
    ].filter((c) => c.value);

    if (colorEntries.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "Nenhuma cor computada.";
      colorsBlock.appendChild(empty);
    } else {
      colorEntries.forEach((c) => {
        const hex = toHex(c.value);
        const toCopy = hex || c.value;

        const row = document.createElement("div");
        row.className = "color-row";

        const swatch = document.createElement("span");
        swatch.className = "swatch";
        swatch.style.background = c.value;

        const label = document.createElement("span");
        label.className = "color-label";
        label.textContent = c.label + ":";

        const value = document.createElement("span");
        value.className = "color-value";
        value.textContent = c.value + (hex ? " (" + hex + ")" : "");

        const copyBtn = document.createElement("button");
        copyBtn.className = "copy-btn";
        copyBtn.textContent = "Copiar";
        copyBtn.addEventListener("click", () => {
          copyText(toCopy).then(() => {
            copyBtn.textContent = "Copiado!";
            setTimeout(() => { copyBtn.textContent = "Copiar"; }, 1200);
          });
        });

        row.appendChild(swatch);
        row.appendChild(label);
        row.appendChild(value);
        row.appendChild(copyBtn);
        colorsBlock.appendChild(row);
      });
    }
    bodyEl.appendChild(colorsBlock);

    [
      { title: "Ancestors", items: chain.slice(0, -1) },
      { title: "Children", items: Array.from(el.children) }
    ].forEach(({ title, items }) => {
      const block = document.createElement("div");
      block.className = "block full";

      const h4 = document.createElement("h4");
      h4.textContent = title;
      block.appendChild(h4);

      if (items.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "Nenhum.";
        block.appendChild(empty);
      } else {
        items.forEach((node) => {
          const item = document.createElement("div");
          item.className = "list-item";
          item.textContent = describeEl(node) || node.tagName.toLowerCase();
          item.addEventListener("click", () => renderInfo(node));
          block.appendChild(item);
        });
      }
      bodyEl.appendChild(block);
    });
  }

  function onClick(e) {
    const path = e.composedPath ? e.composedPath() : [e.target];
    if (path.indexOf(panelHost) !== -1) return;
    e.preventDefault();
    e.stopPropagation();
    const el = document.elementFromPoint(e.clientX, e.clientY);
    if (el) renderInfo(el);
  }

  function onKeyDown(e) {
    if (e.key === "Escape") cleanup();
  }

  function cleanup() {
    document.removeEventListener("mousemove", onMouseMove, true);
    document.removeEventListener("click", onClick, true);
    document.removeEventListener("keydown", onKeyDown, true);
    highlight.remove();
    panelHost.remove();
    window.__sitexrayInspectorActive = false;
  }

  shadow.getElementById("sx-close").addEventListener("click", cleanup);

  document.addEventListener("mousemove", onMouseMove, true);
  document.addEventListener("click", onClick, true);
  document.addEventListener("keydown", onKeyDown, true);
}

async function startInspector() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) return;
  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: startElementInspector
    });
  } catch {
    // Páginas restritas (chrome://, Web Store etc.) bloqueiam injeção de script.
  }
}

async function detectTrackers() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) return [];
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: "MAIN",
      func: scanPageForTrackers
    });
    return result || [];
  } catch {
    return [];
  }
}

function renderTrackers(names) {
  trackersList.innerHTML = "";
  lastTrackers = names || [];
  if (!names || names.length === 0) {
    trackersContainer.classList.add("hidden");
    return;
  }
  const li = document.createElement("li");
  names.forEach((name) => {
    const badge = document.createElement("span");
    badge.className = "tracker-badge";
    badge.textContent = name;
    li.appendChild(badge);
  });
  trackersList.appendChild(li);
  trackersContainer.classList.remove("hidden");
}

function renderTech(names) {
  techList.innerHTML = "";
  lastTechStack = names || [];
  if (!names || names.length === 0) {
    techContainer.classList.add("hidden");
    return;
  }
  const li = document.createElement("li");
  names.forEach((name) => {
    const badge = document.createElement("span");
    badge.className = "tracker-badge";
    badge.textContent = name;
    li.appendChild(badge);
  });
  techList.appendChild(li);
  techContainer.classList.remove("hidden");
}

function renderSecurity(checks) {
  securityList.innerHTML = "";
  lastSecurityChecks = checks;

  checks.forEach((item) => {
    const li = document.createElement("li");
    li.className = "severity-" + (item.ok ? "info" : "warning");

    const row = document.createElement("div");
    row.className = "link-row";

    const label = document.createElement("span");
    label.textContent = item.label;

    const badge = document.createElement("span");
    badge.className = "badge " + (item.ok ? "badge-ok" : "badge-warn");
    badge.textContent = item.ok ? "OK" : "Ausente";

    row.appendChild(label);
    row.appendChild(badge);

    const note = document.createElement("div");
    note.className = "risk-note";
    note.textContent = item.note;

    li.appendChild(row);
    li.appendChild(note);
    securityList.appendChild(li);
  });

  securityContainer.classList.remove("hidden");
}

function addKvRow(list, label, value, missingLabel) {
  const li = document.createElement("li");
  li.className = "kv-row";

  const labelEl = document.createElement("span");
  labelEl.className = "kv-label";
  labelEl.textContent = label;

  const valueEl = document.createElement("span");
  valueEl.className = "kv-value" + (value ? "" : " missing");
  valueEl.textContent = value || missingLabel || "Ausente";

  li.appendChild(labelEl);
  li.appendChild(valueEl);
  list.appendChild(li);
}

function renderSeoSummary(data) {
  seoSummaryList.innerHTML = "";
  if (!data) return;

  addKvRow(seoSummaryList, "Title", data.title ? `${data.title} (${data.title.length} caracteres)` : null);
  addKvRow(seoSummaryList, "Description", data.description ? `${data.description} (${data.description.length} caracteres)` : null);
  addKvRow(seoSummaryList, "Keywords", data.keywords);
  addKvRow(seoSummaryList, "URL", data.url);
  addKvRow(seoSummaryList, "Canonical", data.canonical);
  addKvRow(seoSummaryList, "Robots Tag", data.robotsMeta);
  addKvRow(seoSummaryList, "Author", data.author);
  addKvRow(seoSummaryList, "Publisher", data.publisher);
  addKvRow(seoSummaryList, "Lang", data.lang);

  const headingCounts = [0, 0, 0, 0, 0, 0];
  data.headings.forEach((h) => headingCounts[h.level - 1]++);
  addKvRow(seoSummaryList, "H1-H6", headingCounts.map((c, i) => `H${i + 1}:${c}`).join("  "));
  addKvRow(seoSummaryList, "Imagens", String(data.images.length));
  addKvRow(seoSummaryList, "Links", String(data.links.length));
}

function renderSeoHeaders(headings) {
  seoHeadersList.innerHTML = "";
  if (!headings || headings.length === 0) {
    const li = document.createElement("li");
    li.className = "empty-state";
    li.textContent = "Nenhum heading encontrado.";
    seoHeadersList.appendChild(li);
    return;
  }

  headings.forEach((h) => {
    const li = document.createElement("li");
    li.style.paddingLeft = 8 + (h.level - 1) * 14 + "px";

    const tag = document.createElement("span");
    tag.className = "heading-tag";
    tag.textContent = "H" + h.level;

    li.appendChild(tag);
    li.appendChild(document.createTextNode(h.text));
    seoHeadersList.appendChild(li);
  });
}

function renderSeoImages(images) {
  seoImagesSummary.innerHTML = "";
  seoImagesIssuesList.innerHTML = "";
  seoImagesOkList.innerHTML = "";

  const withoutAlt = images.filter((img) => !img.alt).length;
  const withoutTitle = images.filter((img) => !img.title).length;

  [["Imagens", images.length], ["Sem ALT", withoutAlt], ["Sem Title", withoutTitle]].forEach(([label, value]) => {
    const box = document.createElement("div");
    box.className = "seo-stat";

    const val = document.createElement("div");
    val.className = "seo-stat-value";
    val.textContent = value;

    const lbl = document.createElement("div");
    lbl.className = "seo-stat-label";
    lbl.textContent = label;

    box.appendChild(val);
    box.appendChild(lbl);
    seoImagesSummary.appendChild(box);
  });

  images.forEach((img) => {
    const li = document.createElement("li");
    const hasIssue = !img.alt || !img.title;
    li.className = "severity-" + (hasIssue ? "warning" : "info");

    const row = document.createElement("div");
    row.className = "link-row";
    const name = document.createElement("span");
    name.textContent = (img.src || "").split("/").pop() || img.src || "(sem src)";
    name.title = img.src || "";
    row.appendChild(name);

    const alt = document.createElement("div");
    alt.className = "risk-note";
    alt.textContent = "ALT: " + (img.alt || "ausente");

    const title = document.createElement("div");
    title.className = "risk-note";
    title.textContent = "Title: " + (img.title || "ausente");

    li.appendChild(row);
    li.appendChild(alt);
    li.appendChild(title);

    (hasIssue ? seoImagesIssuesList : seoImagesOkList).appendChild(li);
  });
}

function renderSeoLinks(links) {
  seoLinksList.innerHTML = "";
  [...links]
    .sort((a, b) => b.count - a.count)
    .forEach((l) => {
      const hasStatus = l.status !== undefined;
      const li = document.createElement("li");
      li.className = "severity-" + (hasStatus && !l.statusOk ? "warning" : "info");

      const row = document.createElement("div");
      row.className = "link-row";

      const a = document.createElement("a");
      a.href = l.href;
      a.textContent = l.text;
      a.title = l.href;
      a.addEventListener("click", (e) => {
        e.preventDefault();
        openInBackground(l.href);
      });

      const badgeGroup = document.createElement("span");
      badgeGroup.className = "badge-group";

      const countBadge = document.createElement("span");
      countBadge.className = "badge badge-ok";
      countBadge.textContent = "x" + l.count;
      badgeGroup.appendChild(countBadge);

      if (hasStatus) {
        const statusBadge = document.createElement("span");
        statusBadge.className = "badge " + (l.statusOk ? "badge-ok" : "badge-warn");
        statusBadge.textContent = l.status || "erro";
        badgeGroup.appendChild(statusBadge);
      }

      row.appendChild(a);
      row.appendChild(badgeGroup);

      const urlNote = document.createElement("div");
      urlNote.className = "risk-note";
      urlNote.textContent = l.href;

      li.appendChild(row);
      li.appendChild(urlNote);
      seoLinksList.appendChild(li);
    });
}

function renderSeoSocial(social) {
  seoSocialList.innerHTML = "";
  if (!social || social.length === 0) {
    const li = document.createElement("li");
    li.className = "empty-state";
    li.textContent = "Nenhuma tag Open Graph ou Twitter Card encontrada.";
    seoSocialList.appendChild(li);
    return;
  }
  social.forEach((item) => addKvRow(seoSocialList, item.key, item.value));
}

function renderSeo(data) {
  lastSeoData = data;
  renderSeoSummary(data);
  renderSeoHeaders(data ? data.headings : []);
  renderSeoImages(data ? data.images : []);
  renderSeoLinks(data ? data.links : []);
  renderSeoSocial(data ? data.social : []);
}

// Busca o sitemap por três fontes independentes, na ordem de confiabilidade:
// robots.txt (quando existe) -> tag <link rel="sitemap"> da página -> caminhos padrão.
// Roda sempre, mesmo que o site não seja identificado como WordPress.
async function discoverSitemaps(origin, homepageHtml) {
  const [robotsUrls, fallbackResults] = await Promise.all([
    getSitemapsFromRobots(origin),
    Promise.all(
      SITEMAP_FALLBACK_PATHS.map((entry) => checkAbsoluteUrl(origin + entry.path, entry.label))
    )
  ]);

  const htmlUrls = getSitemapFromHtml(homepageHtml, origin);

  const [robotsResults, htmlResults] = await Promise.all([
    Promise.all(robotsUrls.map((url) => checkAbsoluteUrl(url, "Sitemap (via robots.txt)"))),
    Promise.all(htmlUrls.map((url) => checkAbsoluteUrl(url, "Sitemap (via <link> da página)")))
  ]);

  return dedupeByUrl([...robotsResults, ...htmlResults, ...fallbackResults]).filter((r) => r.ok);
}

function renderSitemapList(results) {
  sitemapList.innerHTML = "";
  lastSitemapResults = results;

  if (results.length === 0) {
    sitemapContainer.classList.add("hidden");
    sitemapEmpty.classList.remove("hidden");
    return;
  }

  results.forEach((r) => {
    const li = document.createElement("li");
    li.className = "severity-info";

    const row = document.createElement("div");
    row.className = "link-row";

    const a = document.createElement("a");
    a.href = r.url;
    a.textContent = r.label;
    a.title = r.url;
    a.addEventListener("click", (e) => {
      e.preventDefault();
      openInBackground(r.url);
    });

    const badge = document.createElement("span");
    badge.className = "badge " + (r.status === 200 ? "badge-ok" : "badge-warn");
    badge.textContent = r.status;

    row.appendChild(a);
    row.appendChild(badge);
    li.appendChild(row);
    sitemapList.appendChild(li);
  });

  sitemapContainer.classList.remove("hidden");
  sitemapEmpty.classList.add("hidden");
}

function renderLinks(results) {
  linksList.innerHTML = "";
  const found = results
    .filter((r) => r.ok)
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  lastFoundResults = found;

  if (found.length === 0) {
    linksContainer.classList.add("hidden");
    emptyState.textContent = "WordPress detectado, mas nenhum dos caminhos verificados respondeu.";
    emptyState.classList.remove("hidden");
    return;
  }

  found.forEach((r) => {
    const li = document.createElement("li");
    li.className = "severity-" + r.severity;

    const row = document.createElement("div");
    row.className = "link-row";

    const a = document.createElement("a");
    a.href = r.url;
    a.textContent = r.label;
    a.title = r.url;
    a.addEventListener("click", (e) => {
      e.preventDefault();
      openInBackground(r.url);
    });

    const badge = document.createElement("span");
    badge.className = "badge " + (r.status === 200 ? "badge-ok" : "badge-warn");
    badge.textContent = r.status;

    row.appendChild(a);
    row.appendChild(badge);

    const sevLabel = document.createElement("div");
    sevLabel.className = "sev-label";
    sevLabel.textContent = SEVERITY_LABEL[r.severity];

    const risk = document.createElement("div");
    risk.className = "risk-note";
    risk.textContent = r.risk || "";

    li.appendChild(row);
    li.appendChild(sevLabel);
    if (r.risk) li.appendChild(risk);
    linksList.appendChild(li);
  });

  linksContainer.classList.remove("hidden");
  emptyState.classList.add("hidden");
}

function buildReport() {
  const lines = [];
  lines.push(`Relatório SiteXray - ${lastOrigin}`);
  lines.push(`Data: ${new Date().toLocaleDateString("pt-BR")}`);
  lines.push("");
  lines.push(
    lastTechStack.length > 0
      ? `Tecnologia detectada: ${lastTechStack.join(", ")}`
      : "Tecnologia detectada: não identificada"
  );

  lines.push("");
  lines.push(lastIsWordPress ? "WordPress: detectado" : "WordPress: não detectado");

  if (lastIsWordPress && lastFoundResults.length > 0) {
    lines.push("");
    lines.push("Links sensíveis encontrados:");
    lastFoundResults.forEach((r) => {
      lines.push(`- [${SEVERITY_LABEL[r.severity]}] ${r.label} (${r.status})${r.risk ? " - " + r.risk : ""}`);
    });
  }

  lines.push("");
  lines.push(
    lastTrackers.length > 0
      ? `Rastreadores/pixels: ${lastTrackers.join(", ")}`
      : "Rastreadores/pixels: nenhum encontrado"
  );

  lines.push("");
  lines.push("Segurança:");
  lastSecurityChecks.forEach((item) => {
    lines.push(`- [${item.ok ? "OK" : "Ausente"}] ${item.label} - ${item.note}`);
  });

  lines.push("");
  lines.push("SEO on-page:");
  if (lastSeoData) {
    const withoutAlt = lastSeoData.images.filter((img) => !img.alt).length;
    lines.push(`- Title: ${lastSeoData.title || "ausente"} (${(lastSeoData.title || "").length} caracteres)`);
    lines.push(`- Description: ${lastSeoData.description ? lastSeoData.description.length + " caracteres" : "ausente"}`);
    lines.push(`- Canonical: ${lastSeoData.canonical || "ausente"}`);
    lines.push(`- H1 na página: ${lastSeoData.headings.filter((h) => h.level === 1).length}`);
    lines.push(`- Imagens sem ALT: ${withoutAlt} de ${lastSeoData.images.length}`);
    lines.push(`- Links na página: ${lastSeoData.links.length}`);
    const brokenLinks = lastSeoData.links.filter((l) => l.status !== undefined && !l.statusOk);
    if (brokenLinks.length > 0) {
      lines.push(`- Links internos com problema (${brokenLinks.length}):`);
      brokenLinks.forEach((l) => lines.push(`  - [${l.status || "erro"}] ${l.href}`));
    }
  } else {
    lines.push("- Não foi possível analisar (script bloqueado nesta página).");
  }

  lines.push("");
  if (lastSitemapResults.length > 0) {
    lines.push("Sitemaps encontrados:");
    lastSitemapResults.forEach((r) => lines.push(`- ${r.url}`));
  } else {
    lines.push("Sitemap: nenhum encontrado");
  }

  return lines.join("\n");
}

async function runScan() {
  statusEl.className = "status status-checking";
  statusEl.textContent = "Verificando o site...";
  linksContainer.classList.add("hidden");
  sitemapContainer.classList.add("hidden");
  sitemapEmpty.classList.add("hidden");
  trackersContainer.classList.add("hidden");
  techContainer.classList.add("hidden");
  securityContainer.classList.add("hidden");
  tabsEl.classList.add("hidden");
  emptyState.classList.add("hidden");
  rescanBtn.classList.add("hidden");
  copyReportBtn.classList.add("hidden");

  const origin = await getActiveTabOrigin();
  if (!origin) {
    statusEl.className = "status status-not-found";
    statusEl.textContent = "Não foi possível ler a aba atual (URL inválida).";
    rescanBtn.classList.remove("hidden");
    return;
  }

  lastOrigin = origin;
  originEl.textContent = origin;

  // O link de WHOIS não depende de ser WordPress, então já deixa disponível.
  const hostname = new URL(origin).hostname;
  whoisLinkEl.href = "https://who.is/whois/" + hostname;
  defaultSitemapLinkEl.href = origin + "/sitemap.xml";
  googleSiteLinkEl.href = "https://www.google.com/search?q=" + encodeURIComponent("site:" + hostname);
  domainToolsEl.classList.remove("hidden");
  tabsEl.classList.remove("hidden");

  // Trackers/pixels e SEO on-page são verificados independente do site ser WordPress ou não.
  detectTrackers().then(renderTrackers);
  scanSeo().then(async (data) => {
    renderSeo(data);
    if (data && data.links.length > 0) {
      await checkLinkStatuses(data.links, origin);
      renderSeoLinks(data.links);
    }
  });

  const { html: homepageHtml, headers } = await fetchHomepage(origin);

  // Sitemap também é independente: roda mesmo que a detecção de WP falhe.
  discoverSitemaps(origin, homepageHtml).then(renderSitemapList);

  const [isWordPress, httpsForced] = await Promise.all([
    detectWordPress(origin, homepageHtml),
    checkHttpsForced(origin)
  ]);
  lastIsWordPress = isWordPress;

  const techStack = detectTechStack(homepageHtml, headers);
  if (isWordPress) techStack.unshift("WordPress");
  renderTech(techStack);
  renderSecurity(buildSecurityChecks(headers, httpsForced));

  if (!isWordPress) {
    statusEl.className = "status status-not-found";
    statusEl.textContent = "Este site não parece ser WordPress.";
    rescanBtn.classList.remove("hidden");
    copyReportBtn.classList.remove("hidden");
    return;
  }

  statusEl.className = "status status-found";
  statusEl.textContent = "WordPress detectado. Checando links públicos...";

  const pathResults = await Promise.all(CANDIDATE_PATHS.map((entry) => checkPath(origin, entry)));
  const results = dedupeByUrl(pathResults);

  statusEl.textContent = "WordPress detectado.";
  renderLinks(results);
  rescanBtn.classList.remove("hidden");
  copyReportBtn.classList.remove("hidden");
}

rescanBtn.addEventListener("click", runScan);

whoisLinkEl.addEventListener("click", (e) => {
  e.preventDefault();
  openInBackground(whoisLinkEl.href);
});

defaultSitemapLinkEl.addEventListener("click", (e) => {
  e.preventDefault();
  openInBackground(defaultSitemapLinkEl.href);
});

googleSiteLinkEl.addEventListener("click", (e) => {
  e.preventDefault();
  openInBackground(googleSiteLinkEl.href);
});

openAllBtn.addEventListener("click", () => {
  lastFoundResults.forEach((r) => openInBackground(r.url));
});

openAllSitemapBtn.addEventListener("click", () => {
  lastSitemapResults.forEach((r) => openInBackground(r.url));
});

startInspectorBtn.addEventListener("click", startInspector);

copyReportBtn.addEventListener("click", async () => {
  const original = copyReportBtn.textContent;
  try {
    await navigator.clipboard.writeText(buildReport());
    copyReportBtn.textContent = "✅ Copiado!";
  } catch {
    copyReportBtn.textContent = "Erro ao copiar";
  }
  setTimeout(() => {
    copyReportBtn.textContent = original;
  }, 1500);
});

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.remove("hidden");
  });
});

document.querySelectorAll(".subtab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".subtab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".subtab-panel").forEach((p) => p.classList.add("hidden"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.subtab).classList.remove("hidden");
  });
});

document.addEventListener("DOMContentLoaded", runScan);
