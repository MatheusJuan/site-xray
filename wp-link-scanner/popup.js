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
const techContainer = document.getElementById("tech-container");
const techList = document.getElementById("tech-list");
const securityContainer = document.getElementById("security-container");
const securityList = document.getElementById("security-list");

let lastSitemapResults = [];

let lastFoundResults = [];

let lastTrackers = [];
let lastTechStack = [];
let lastSecurityChecks = [];
let lastIsWordPress = false;
let lastOrigin = "";

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

  // Trackers/pixels são verificados independente do site ser WordPress ou não.
  detectTrackers().then(renderTrackers);

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

document.addEventListener("DOMContentLoaded", runScan);
