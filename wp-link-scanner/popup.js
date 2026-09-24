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
const SUBDOMAIN_DISPLAY_CAP = 60;

const REPO_URL = "https://github.com/MatheusJuan/site-xray";
const REPO_MANIFEST_URL = "https://raw.githubusercontent.com/MatheusJuan/site-xray/master/wp-link-scanner/manifest.json";

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
  { name: "React", test: ({ html }) => /data-reactroot|data-react-|__REACT_DEVTOOLS|react-dom(?:\.production)?(?:\.min)?\.js/i.test(html || "") },
  { name: "Svelte", test: ({ html }) => /__svelte|svelte-[a-z0-9]{6}|\/_app\/immutable\//i.test(html || "") },
  { name: "Astro", test: ({ html }) => /astro-island|data-astro/i.test(html || "") },
  { name: "Laravel", test: ({ html }) => /laravel_session|XSRF-TOKEN|content="Laravel/i.test(html || "") },
  { name: "Django", test: ({ html, headers }) => /csrfmiddlewaretoken/i.test(html || "") || /csrftoken/i.test(headers["set-cookie"] || "") },
  { name: "Ruby on Rails", test: ({ html }) => /csrf-token[^>]+name="csrf-token"|rails-ujs/i.test(html || "") },
  { name: "Livewire", test: ({ html }) => /livewire\.js|wire:id/i.test(html || "") },

  // E-commerce
  { name: "WooCommerce", test: ({ html }) => /woocommerce/i.test(html || "") },
  { name: "PrestaShop", test: ({ html }) => /PrestaShop|\/modules\/ps_/i.test(html || "") },
  { name: "Magento", test: ({ html }) => /Mage\.Cookies|\/skin\/frontend\//i.test(html || "") },

  // CSS framework
  { name: "Bootstrap", test: ({ html }) => /bootstrap(\.min)?\.css|bootstrap\.bundle/i.test(html || "") },
  { name: "Tailwind CSS", test: ({ html }) => /tailwind(?:\.min)?\.css|cdn\.tailwindcss\.com/i.test(html || "") },
  { name: "Bulma", test: ({ html }) => /bulma(?:\.min)?\.css/i.test(html || "") },
  { name: "Foundation", test: ({ html }) => /foundation(?:\.min)?\.css/i.test(html || "") },

  // JS libs comuns
  { name: "jQuery", test: ({ html }) => /jquery(?:[-.][\d.]+)?(?:\.min)?\.js|\/jquery-/i.test(html || "") },
  { name: "Alpine.js", test: ({ html }) => /alpinejs(?:\.min)?\.js|x-data=/i.test(html || "") },
  { name: "htmx", test: ({ html }) => /htmx(?:\.min)?\.js|hx-get=/i.test(html || "") },
  { name: "Three.js", test: ({ html }) => /three(?:\.min)?\.js|THREE\./i.test(html || "") },

  // CDN / hosting
  { name: "Cloudflare", test: ({ headers }) => !!headers["cf-ray"] || /cloudflare/i.test(headers["server"] || "") },
  { name: "Vercel", test: ({ headers }) => !!headers["x-vercel-id"] || /vercel/i.test(headers["server"] || "") },
  { name: "Netlify", test: ({ headers }) => !!headers["x-nf-request-id"] || /netlify/i.test(headers["server"] || "") },
  { name: "Fastly", test: ({ headers }) => !!headers["x-fastly-request-id"] || /fastly/i.test(headers["x-served-by"] || "") },
  { name: "Amazon CloudFront", test: ({ headers }) => !!headers["x-amz-cf-id"] || /cloudfront/i.test(headers["via"] || "") },
  { name: "Hostinger", test: ({ headers }) => /hostinger/i.test(headers["server"] || headers["x-powered-by"] || "") },
  { name: "SiteGround", test: ({ headers }) => /siteground|sg-cdn/i.test(headers["server"] || headers["via"] || "") }
];

const SECURITY_HEADERS = [
  { key: "strict-transport-security", label: "Strict-Transport-Security (HSTS)", penalty: 12 },
  { key: "content-security-policy", label: "Content-Security-Policy", penalty: 12 },
  { key: "x-frame-options", label: "X-Frame-Options", penalty: 12 },
  { key: "x-content-type-options", label: "X-Content-Type-Options", penalty: 12 },
  { key: "referrer-policy", label: "Referrer-Policy", penalty: 12 },
  { key: "permissions-policy", label: "Permissions-Policy", penalty: 12 },
  // Avançados: mostrados como recomendação, sem descontar da nota (penalty 0).
  { key: "cross-origin-opener-policy", label: "Cross-Origin-Opener-Policy", penalty: 0 },
  { key: "cross-origin-resource-policy", label: "Cross-Origin-Resource-Policy", penalty: 0 },
  { key: "cross-origin-embedder-policy", label: "Cross-Origin-Embedder-Policy", penalty: 0 }
];

// Integrações úteis pro cliente (pagamento, chat, CRM, maps…).
// Diferente de trackers: aqui o foco é o que o site "usa de produto".
const INTEGRATION_SIGNATURES = [
  { name: "Mercado Pago", cat: "pagamento", test: ({ html }) => /mercadopago|static\.mercadolivre|mercadolivre\.com\.br.*checkout/i.test(html || "") },
  { name: "Stripe", cat: "pagamento", test: ({ html }) => /js\.stripe\.com|stripe\.com\/v3/i.test(html || "") },
  { name: "PagBank / PagSeguro", cat: "pagamento", test: ({ html }) => /pagseguro|pagbank/i.test(html || "") },
  { name: "Pagar.me", cat: "pagamento", test: ({ html }) => /pagar\.me/i.test(html || "") },
  { name: "Asaas", cat: "pagamento", test: ({ html }) => /asaas\.com/i.test(html || "") },
  { name: "VTEX", cat: "e-commerce", test: ({ html }) => /vtex/i.test(html || "") },
  { name: "Nuvemshop", cat: "e-commerce", test: ({ html }) => /nuvemshop|tiendanube/i.test(html || "") },
  { name: "WhatsApp", cat: "contato", test: ({ html }) => /wa\.me|api\.whatsapp\.com|whatsapp\.com\/send/i.test(html || "") },
  { name: "Tidio", cat: "chat", test: ({ html }) => /tidio/i.test(html || "") },
  { name: "Tawk.to", cat: "chat", test: ({ html }) => /tawk\.to/i.test(html || "") },
  { name: "Crisp", cat: "chat", test: ({ html }) => /crisp\.chat/i.test(html || "") },
  { name: "HubSpot", cat: "crm", test: ({ html }) => /js\.hs-scripts|hubspot|hs-analytics/i.test(html || "") },
  { name: "RD Station", cat: "crm", test: ({ html }) => /rdstation|rd\.station/i.test(html || "") },
  { name: "Mailchimp", cat: "e-mail", test: ({ html }) => /list-manage\.com|mailchimp/i.test(html || "") },
  { name: "Brevo", cat: "e-mail", test: ({ html }) => /sendinblue|brevo\.com/i.test(html || "") },
  { name: "ActiveCampaign", cat: "e-mail", test: ({ html }) => /activecampaign/i.test(html || "") },
  { name: "Google Maps", cat: "widget", test: ({ html }) => /maps\.googleapis|maps\.google\.com|google\.com\/maps/i.test(html || "") },
  { name: "YouTube embed", cat: "widget", test: ({ html }) => /youtube\.com\/embed|ytimg\.com\/embed/i.test(html || "") },
  { name: "reCAPTCHA", cat: "segurança", test: ({ html }) => /recaptcha|google\.com\/recaptcha/i.test(html || "") },
  { name: "hCaptcha", cat: "segurança", test: ({ html }) => /hcaptcha\.com/i.test(html || "") },
  { name: "Cloudflare Turnstile", cat: "segurança", test: ({ html }) => /turnstile|challenges\.cloudflare\.com/i.test(html || "") },
  { name: "Calendly", cat: "agendamento", test: ({ html }) => /calendly/i.test(html || "") },
  { name: "Google Tag Manager", cat: "tag", test: ({ html }) => /googletagmanager\.com|gtm\.js/i.test(html || "") }
];

const AI_BOT_NAMES = [
  "GPTBot", "ChatGPT-User", "ClaudeBot", "Claude-User", "anthropic-ai",
  "Google-Extended", "CCBot", "PerplexityBot", "Bytespider",
  "meta-externalagent", "Applebot-Extended", "Amazonbot", "YouBot", "cohere-ai"
];

// Caminhos públicos que nunca deveriam responder. `valid` olha o começo do
// corpo, porque SPAs devolvem 200 com index.html pra qualquer rota e isso
// daria falso positivo se só o status contasse.
const SENSITIVE_PATHS = [
  { path: "/.env", label: ".env", severity: "critical", risk: "Variáveis de ambiente (senhas, chaves de API) expostas.", valid: (t) => /^[A-Z][A-Z0-9_]*\s*=/m.test(t) && !/<html/i.test(t) },
  { path: "/.git/config", label: ".git/config", severity: "critical", risk: "Repositório Git exposto, permite baixar o código-fonte.", valid: (t) => /\[core\]/i.test(t) },
  { path: "/.git/HEAD", label: ".git/HEAD", severity: "critical", risk: "Repositório Git exposto, permite baixar o código-fonte.", valid: (t) => /^ref:\s*refs\//.test(t.trim()) },
  { path: "/.htpasswd", label: ".htpasswd", severity: "critical", risk: "Hashes de senha do servidor expostos.", valid: (t) => /^[^:\s<]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13})/m.test(t) },
  { path: "/wp-config.php.bak", label: "wp-config.php.bak", severity: "critical", risk: "Backup do wp-config com credenciais do banco.", valid: (t) => /DB_NAME|DB_PASSWORD/.test(t) },
  { path: "/backup.sql", label: "backup.sql", severity: "critical", risk: "Dump de banco de dados exposto.", valid: (t) => /CREATE TABLE|INSERT INTO|MySQL dump/i.test(t) },
  { path: "/db.sql", label: "db.sql", severity: "critical", risk: "Dump de banco de dados exposto.", valid: (t) => /CREATE TABLE|INSERT INTO|MySQL dump/i.test(t) },
  { path: "/backup.zip", label: "backup.zip", severity: "critical", risk: "Backup do site exposto para download.", valid: (t) => t.startsWith("PK") },
  { path: "/phpinfo.php", label: "phpinfo.php", severity: "warning", risk: "Revela versão do PHP, módulos e caminhos do servidor.", valid: (t) => /phpinfo\(\)|PHP Version/i.test(t) },
  { path: "/server-status", label: "server-status", severity: "warning", risk: "Painel de status do Apache exposto.", valid: (t) => /Apache Server Status/i.test(t) }
];

// Nomes de parâmetro que costumam alimentar redirecionamento.
const REDIRECT_PARAMS = ["redirect", "redirect_uri", "redirect_url", "return", "returnurl", "return_to", "next", "url", "continue", "dest", "destination", "goto"];

const statusEl = document.getElementById("status");
const originEl = document.getElementById("site-origin");
const linksContainer = document.getElementById("links-container");
const linksList = document.getElementById("links-list");
const emptyState = document.getElementById("empty-state");
const rescanBtn = document.getElementById("rescan");
const domainToolsEl = document.getElementById("domain-tools");
const whoisLinkEl = document.getElementById("whois-link");
const dnsCheckerLinkEl = document.getElementById("dns-checker-link");
const defaultSitemapLinkEl = document.getElementById("default-sitemap-link");
const googleSiteLinkEl = document.getElementById("google-site-link");
const openAllBtn = document.getElementById("open-all-btn");
const trackersContainer = document.getElementById("trackers-container");
const trackersList = document.getElementById("trackers-list");
const sitemapContainer = document.getElementById("sitemap-container");
const sitemapList = document.getElementById("sitemap-list");
const sitemapEmpty = document.getElementById("sitemap-empty");
const openAllSitemapBtn = document.getElementById("open-all-sitemap-btn");
const subdomainsContainer = document.getElementById("subdomains-container");
const subdomainsList = document.getElementById("subdomains-list");
const subdomainsEmpty = document.getElementById("subdomains-empty");
const openAllSubdomainsBtn = document.getElementById("open-all-subdomains-btn");
const copyReportBtn = document.getElementById("copy-report-btn");
const exportReportBtn = document.getElementById("export-report-btn");
const exportHtmlBtn = document.getElementById("export-html-btn");
const securityGradeEl = document.getElementById("security-grade");
const gradeLetterEl = document.getElementById("grade-letter");
const gradeLabelEl = document.getElementById("grade-label");
const gradeScoreEl = document.getElementById("grade-score");
const startInspectorBtn = document.getElementById("start-inspector-btn");
const devBtn = document.getElementById("dev-btn");
const devPanel = document.getElementById("dev-panel");
const devVersionEl = document.getElementById("dev-version");
const devUpdateStatusEl = document.getElementById("dev-update-status");
const devRepoLinkEl = document.getElementById("dev-repo-link");
const techContainer = document.getElementById("tech-container");
const techList = document.getElementById("tech-list");
const perfContainer = document.getElementById("perf-container");
const perfList = document.getElementById("perf-list");
const thirdPartyContainer = document.getElementById("thirdparty-container");
const thirdPartyList = document.getElementById("thirdparty-list");
const securityContainer = document.getElementById("security-container");
const securityList = document.getElementById("security-list");
const sensitiveList = document.getElementById("sensitive-list");
const cookiesList = document.getElementById("cookies-list");
const redirectsList = document.getElementById("redirects-list");
const tabsEl = document.getElementById("tabs");
const seoSummaryList = document.getElementById("seo-summary-list");
const seoHeadersList = document.getElementById("seo-headers-list");
const seoImagesSummary = document.getElementById("seo-images-summary");
const seoImagesIssuesList = document.getElementById("seo-images-issues-list");
const seoImagesOkList = document.getElementById("seo-images-ok-list");
const seoLinksList = document.getElementById("seo-links-list");
const seoSocialList = document.getElementById("seo-social-list");
const seoFaviconImg = document.getElementById("seo-favicon-img");
const seoFaviconDownloadBtn = document.getElementById("seo-favicon-download-btn");
const seoHeadTbody = document.getElementById("seo-head-tbody");
const seoJsonldList = document.getElementById("seo-jsonld-list");
const pluginsContainer = document.getElementById("plugins-container");
const pluginsList = document.getElementById("plugins-list");
const mixedContainer = document.getElementById("mixed-container");
const mixedList = document.getElementById("mixed-list");
const robotsContainer = document.getElementById("robots-container");
const robotsList = document.getElementById("robots-list");
const pagespeedContainer = document.getElementById("pagespeed-container");
const pagespeedList = document.getElementById("pagespeed-list");
const runPagespeedBtn = document.getElementById("run-pagespeed-btn");
const historyContainer = document.getElementById("history-container");
const historyList = document.getElementById("history-list");
const dnsContainer = document.getElementById("dns-container");
const dnsList = document.getElementById("dns-list");
const integrationsContainer = document.getElementById("integrations-container");
const integrationsList = document.getElementById("integrations-list");
const contactContainer = document.getElementById("contact-container");
const contactList = document.getElementById("contact-list");
const aiContainer = document.getElementById("ai-container");
const aiList = document.getElementById("ai-list");

let lastSitemapResults = [];
let lastSubdomains = [];

let lastFoundResults = [];

let lastTrackers = [];
let lastTechStack = [];
let lastSecurityChecks = [];
let lastSensitiveFiles = [];
let lastCookies = [];
let lastRedirectCandidates = [];
let lastIsWordPress = false;
let lastOrigin = "";
let lastSeoData = null;
let lastPerf = null;
let lastWpPlugins = [];
let lastWpThemes = [];
let lastMixedContent = [];
let lastRobots = null;
let lastPageSpeed = null;
let lastEmailDns = null;
let lastIntegrations = [];
let lastContact = null;
let lastAiInfo = null;
let scanId = 0;

const CACHE_TTL_MS = 10 * 60 * 1000;

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

// Segue a cadeia de redirect à mão e mescla os headers de todas as
// respostas. Sem isso, headers como HSTS vindos só no 3xx (comum em
// Cloudflare) sumiam quando o fetch automático pousava no destino final.
async function fetchHomepage(origin) {
  const mergeHeaders = (target, res) => {
    res.headers.forEach((value, key) => {
      const k = key.toLowerCase();
      if (!(k in target) && value !== "") target[k] = value;
    });
  };

  const readBody = async (res) => {
    if (!res.ok) return null;
    try {
      return await res.text();
    } catch {
      return null;
    }
  };

  try {
    const first = await fetchWithTimeout(origin + "/", { redirect: "manual" });

    // opaqueredirect (status 0) não expõe headers/location: cai no automático.
    if (first.status === 0) throw new Error("opaque-redirect");

    const headers = {};
    mergeHeaders(headers, first);

    const location = first.headers.get("location");
    if (first.status >= 300 && first.status < 400 && location) {
      const dest = new URL(location, origin + "/").href;
      try {
        const res = await fetchWithTimeout(dest);
        mergeHeaders(headers, res);
        return { html: await readBody(res), headers };
      } catch {
        return { html: null, headers };
      }
    }

    return { html: await readBody(first), headers };
  } catch {
    // Fallback: deixa o navegador seguir os redirects sozinho.
    try {
      const res = await fetchWithTimeout(origin + "/");
      const headers = {};
      mergeHeaders(headers, res);
      return { html: await readBody(res), headers };
    } catch {
      return { html: null, headers: {} };
    }
  }
}

// HSTS nem sempre aparece em response.headers do fetch da extensão
// (cross-origin sem Access-Control-Expose-Headers; redirect:manual vira
// opaqueredirect status 0). Sonda same-origin na própria página, que
// enxerga todos os headers no 200 final (HSTS costuma vir nos dois hops).
async function probePageSecurityHeaders() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) return {};
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: async () => {
        try {
          const res = await fetch(location.origin + "/", {
            redirect: "follow",
            cache: "no-store"
          });
          const headers = {};
          res.headers.forEach((value, key) => {
            const k = key.toLowerCase();
            if (value !== "") headers[k] = value;
          });
          return headers;
        } catch {
          return {};
        }
      }
    });
    return result || {};
  } catch {
    return {};
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
  if (headers["x-powered-by"]) matches.push(headers["x-powered-by"]);

  return [...new Set(matches)];
}

// Extrai plugins e tema ativo do WordPress a partir dos caminhos
// wp-content/plugins/<nome>/ e wp-content/themes/<nome>/ no HTML da home.
function detectWpComponents(html) {
  const plugins = new Set();
  const themes = new Set();
  if (!html) return { plugins: [], themes: [] };
  const pluginRe = /wp-content\/plugins\/([a-z0-9_-]+)\//gi;
  const themeRe = /wp-content\/themes\/([a-z0-9_-]+)\//gi;
  let m;
  while ((m = pluginRe.exec(html))) plugins.add(m[1]);
  while ((m = themeRe.exec(html))) themes.add(m[1]);
  return { plugins: [...plugins].sort(), themes: [...themes].sort() };
}

// Recursos http:// em página https = mixed content (navegador bloqueia
// passivos, ativos dão aviso no console). Só olha o HTML estático da home.
function findMixedContent(html, origin) {
  if (!origin.startsWith("https:") || !html) return [];
  const found = new Set();
  const re = /(?:src|href|poster|data-src)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
  let m;
  while ((m = re.exec(html))) found.add(m[1]);
  return [...found].slice(0, 20);
}

// robots.txt: Disallow/Allow por User-agent, Host e Crawl-delay.
// Sitemap já é tratado por getSitemapsFromRobots.
function parseRobots(text) {
  if (!text) return null;
  const lines = text.split(/\r?\n/);
  let currentUser = "*";
  const agents = {};
  let host = null;
  let crawlDelay = null;
  let disallowTotal = 0;
  let allowTotal = 0;

  const ensure = (name) => agents[name] || (agents[name] = { disallow: [], allow: [], crawlDelay: null });

  for (const raw of lines) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();

    if (key === "user-agent") {
      currentUser = value || "*";
      ensure(currentUser);
    } else if (key === "disallow") {
      const a = ensure(currentUser);
      if (value !== "") {
        a.disallow.push(value);
        disallowTotal++;
      }
    } else if (key === "allow") {
      const a = ensure(currentUser);
      if (value !== "") {
        a.allow.push(value);
        allowTotal++;
      }
    } else if (key === "crawl-delay") {
      const n = Number(value);
      if (!Number.isNaN(n)) {
        ensure(currentUser).crawlDelay = n;
        if (crawlDelay === null) crawlDelay = n;
      }
    } else if (key === "host") {
      if (!host) host = value;
    }
  }

  return {
    agents: Object.entries(agents).map(([name, data]) => ({ name, ...data })),
    host,
    crawlDelay,
    disallowTotal,
    allowTotal,
    hasDisallow: disallowTotal > 0
  };
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
  const csp = headers["content-security-policy"] || "";
  const checks = SECURITY_HEADERS.map((h) => {
    const present = !!headers[h.key];
    const penalty = h.penalty != null ? h.penalty : 12;
    let note;
    if (!present) {
      note = penalty === 0
        ? "Recomendado (não afeta a nota)."
        : "Ausente, recomenda-se configurar.";
    } else if (h.key === "content-security-policy") {
      const issues = analyzeCspIssues(csp);
      note = issues.length
        ? "Presente, mas com riscos: " + issues.join(", ") + "."
        : "Presente. Sem unsafe-inline/eval aparente.";
    } else {
      note = "Presente.";
    }
    return { label: h.label, ok: present, note, penalty };
  });

  checks.push({
    label: "HTTPS forçado",
    ok: httpsForced,
    note: httpsForced ? "http:// redireciona para https://." : "http:// não redireciona para https://.",
    penalty: 12
  });

  if (csp) {
    const issues = analyzeCspIssues(csp);
    if (issues.length) {
      checks.push({
        label: "Qualidade da CSP",
        ok: false,
        note: "Riscos: " + issues.join(", ") + ". Vale revisar a política.",
        penalty: 4
      });
    }
  }

  return checks;
}

function analyzeCspIssues(csp) {
  if (!csp) return [];
  const issues = [];
  if (/unsafe-inline/i.test(csp)) issues.push("unsafe-inline");
  if (/unsafe-eval/i.test(csp)) issues.push("unsafe-eval");
  const scriptSrc = csp
    .split(";")
    .map((s) => s.trim())
    .find((d) => /^script-src(?:-elem|-attr)?\b/i.test(d) || /^default-src\b/i.test(d));
  if (scriptSrc && /(^|[\s'])\*(?![0-9a-z-])/i.test(scriptSrc) && !/nonce-|'strict-dynamic'/i.test(scriptSrc)) {
    issues.push("wildcard em script/default-src");
  }
  return issues;
}

function computeSecurityGrade() {
  if (!lastSecurityChecks.length) return null;
  let score = 100;
  lastSecurityChecks.forEach((c) => {
    if (!c.ok) score -= c.penalty != null ? c.penalty : 12;
  });
  lastSensitiveFiles.forEach((f) => {
    if (f.severity === "critical") score -= 15;
    else if (f.severity === "warning") score -= 8;
  });
  const weakCookies = lastCookies.filter(
    (c) => !c.secure || !(c.sameSite === "lax" || c.sameSite === "strict")
  );
  score -= weakCookies.length * 3;
  score = Math.max(0, Math.min(100, score));
  let grade = "F";
  if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 70) grade = "C";
  else if (score >= 60) grade = "D";
  return { score, grade, weakCookies: weakCookies.length };
}

function updateSecurityGrade() {
  const g = computeSecurityGrade();
  if (!g) {
    securityGradeEl.classList.add("hidden");
    return;
  }
  securityGradeEl.classList.remove("hidden");
  gradeLetterEl.textContent = g.grade;
  gradeLetterEl.className = "grade-letter grade-" + g.grade.toLowerCase();
  gradeLabelEl.textContent =
    g.grade === "A" ? "Excelente" :
    g.grade === "B" ? "Bom" :
    g.grade === "C" ? "Regular" :
    g.grade === "D" ? "Fraco" : "Crítico";
  gradeScoreEl.textContent = g.score + "/100";
}

// Lê só o primeiro chunk do corpo (até maxBytes) e cancela o resto, pra não
// baixar um backup.zip inteiro só pra checar a assinatura "PK".
// ponytail: se o servidor mandar o primeiro chunk muito pequeno, a validação
// pode dar falso negativo. Aceitável pra checagem passiva.
async function readHead(res, maxBytes = 4096) {
  const reader = res.body.getReader();
  const { value } = await reader.read();
  reader.cancel();
  return new TextDecoder().decode(value ? value.slice(0, maxBytes) : new Uint8Array());
}

async function checkSensitiveFiles(origin) {
  const results = await Promise.all(
    SENSITIVE_PATHS.map(async (entry) => {
      const url = origin + entry.path;
      try {
        const res = await fetchWithTimeout(url);
        if (!res.ok) return null;
        const text = await readHead(res);
        return entry.valid(text) ? { ...entry, url } : null;
      } catch {
        return null;
      }
    })
  );
  return results.filter(Boolean);
}

// Nunca lê nem guarda o valor do cookie, só nome e flags.
async function getCookieFlags(origin) {
  try {
    const cookies = await chrome.cookies.getAll({ url: origin });
    return cookies.map((c) => ({
      name: c.name,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite
    }));
  } catch {
    return [];
  }
}

function findRedirectCandidates(links, origin) {
  const seen = new Set();
  const found = [];
  links.forEach((l) => {
    try {
      const u = new URL(l.href);
      if (u.origin !== origin || seen.has(l.href)) return;
      for (const key of u.searchParams.keys()) {
        if (REDIRECT_PARAMS.includes(key.toLowerCase())) {
          seen.add(l.href);
          found.push({ href: l.href, param: key });
          break;
        }
      }
    } catch {
      // href inválido, ignora
    }
  });
  return found;
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

async function fetchRobotsAnalysis(origin) {
  try {
    const res = await fetchWithTimeout(origin + "/robots.txt");
    if (!res.ok) return null;
    const text = await res.text();
    return parseRobots(text);
  } catch {
    return null;
  }
}

function detectIntegrations(html, headers) {
  return INTEGRATION_SIGNATURES.filter((s) => {
    try {
      return !!s.test({ html, headers });
    } catch {
      return false;
    }
  }).map((s) => ({ name: s.name, cat: s.cat }));
}

function extractContactInfo(html) {
  const emails = new Set();
  if (html) {
    const re = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    let m;
    while ((m = re.exec(html))) {
      const e = m[0].toLowerCase();
      if (/\.(png|jpe?g|gif|svg|webp|css|js|woff2?)$/i.test(e)) continue;
      if (/(example\.(com|org)|sentry|w3\.org|schema\.org|googleapis|cloudflare|domain\.com)/i.test(e)) continue;
      emails.add(e);
    }
    const mailtoRe = /href=["']mailto:([^"'?]+)/gi;
    while ((m = mailtoRe.exec(html))) emails.add(m[1].toLowerCase());
  }

  const privacy = [];
  if (html) {
    const linkRe = /<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = linkRe.exec(html))) {
      const href = m[1];
      const text = m[2].replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
      if (/privacidade|privacy|termos[- ]de[- ]uso|terms|lgpd|cookie[- ]?policy|pol[ií]tica/i.test(href + " " + text)) {
        privacy.push({ href, text: text || href });
      }
    }
  }

  const seen = new Set();
  const privacyDeduped = privacy.filter((p) => {
    const k = (p.text + "|" + p.href).toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return { emails: [...emails].slice(0, 20), privacy: privacyDeduped.slice(0, 12) };
}

function detectAiBots(text) {
  if (!text) return [];
  const found = [];
  let name = null;
  const disallows = [];
  const flush = () => {
    if (!name) return;
    const lower = name.toLowerCase();
    const known = AI_BOT_NAMES.find((b) => lower === b.toLowerCase() || lower.startsWith(b.toLowerCase()));
    if (known) {
      const blocked = disallows.some((d) => d === "/" || d === "");
      found.push({ name, blocked });
    }
    name = null;
    disallows.length = 0;
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const ua = line.match(/^user-agent\s*:\s*(\S+)/i);
    if (ua) {
      flush();
      name = ua[1];
      continue;
    }
    const dis = line.match(/^disallow\s*:\s*(.*)/i);
    if (dis && name) disallows.push(dis[1].trim());
  }
  flush();
  const seen = new Set();
  return found.filter((f) => {
    const k = f.name.toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

async function fetchRobotsRaw(origin) {
  try {
    const res = await fetchWithTimeout(origin + "/robots.txt");
    if (!res.ok) return "";
    return await res.text();
  } catch {
    return "";
  }
}

async function checkLlmsTxt(origin) {
  try {
    const res = await fetchWithTimeout(origin + "/llms.txt");
    if (!res.ok) return { present: false };
    const text = await res.text();
    if (!text || text.trim().length < 8) return { present: false };
    const title = (text.match(/^#\s+(.+)$/m) || [])[1] || "";
    return { present: true, title: title.trim().slice(0, 120), lines: text.split(/\r?\n/).filter(Boolean).length };
  } catch {
    return { present: false };
  }
}

async function dohQuery(name, type) {
  try {
    const res = await fetchWithTimeout(
      "https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=" + type
    );
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// MX/SPF/DMARC via DNS-over-HTTPS: resolve sem precisar de dig/nslookup.
async function lookupEmailAuth(hostname) {
  const [mx, txt, dmarc] = await Promise.all([
    dohQuery(hostname, "MX"),
    dohQuery(hostname, "TXT"),
    dohQuery("_dmarc." + hostname, "TXT")
  ]);

  const answers = (data) => (data && Array.isArray(data.Answer) ? data.Answer : []);

  const mxRecords = answers(mx)
    .filter((a) => a.type === 15)
    .map((a) => {
      const s = String(a.data || "").trim();
      const parts = s.split(/\s+/);
      const host = parts.length > 1 ? parts.slice(1).join(" ") : s;
      return host.replace(/\.$/, "");
    })
    .filter(Boolean);

  const spf = answers(txt)
    .filter((a) => a.type === 16)
    .map((a) => String(a.data || "").replace(/^"|"$/g, ""))
    .find((v) => /^v=spf1/i.test(v)) || null;

  const dmarcRec = answers(dmarc)
    .filter((a) => a.type === 16)
    .map((a) => String(a.data || "").replace(/^"|"$/g, ""))
    .find((v) => /^v=DMARC1/i.test(v)) || null;

  return {
    mx: mxRecords.slice(0, 6),
    spf,
    dmarc: dmarcRec,
    hasMx: mxRecords.length > 0,
    hasSpf: !!spf,
    hasDmarc: !!dmarcRec
  };
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

function compareVersions(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

// Compara a versão instalada com o manifest.json direto do repo no GitHub.
// Sem API do GitHub (rate limit), só o arquivo raw, com cache-buster.
async function checkForUpdate() {
  const installedVersion = chrome.runtime.getManifest().version;
  devVersionEl.textContent = installedVersion;

  try {
    const res = await fetchWithTimeout(REPO_MANIFEST_URL + "?_=" + Date.now());
    if (!res.ok) throw new Error("resposta não ok");
    const remoteManifest = await res.json();
    if (compareVersions(remoteManifest.version, installedVersion) > 0) {
      devUpdateStatusEl.textContent = "🔴 Atualização disponível: v" + remoteManifest.version;
      devBtn.classList.add("update-available");
    } else {
      devUpdateStatusEl.textContent = "✅ Você está na versão mais recente.";
    }
  } catch {
    devUpdateStatusEl.textContent = "Não foi possível checar atualização.";
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

// Roda dentro da própria página (world: MAIN). Lê LCP/CLS/TTFB já registrados
// (buffered) e agrupa por host os recursos de outros domínios.
function scanPagePerformance() {
  return new Promise((resolve) => {
    let lcp = null;
    let cls = 0;
    const observers = [];
    try {
      const lcpObs = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        if (entries.length) lcp = entries[entries.length - 1].startTime;
      });
      lcpObs.observe({ type: "largest-contentful-paint", buffered: true });
      const clsObs = new PerformanceObserver((list) => {
        list.getEntries().forEach((e) => { if (!e.hadRecentInput) cls += e.value; });
      });
      clsObs.observe({ type: "layout-shift", buffered: true });
      observers.push(lcpObs, clsObs);
    } catch {
      // Navegador sem suporte a esses tipos: segue só com TTFB e terceiros.
    }
    setTimeout(() => {
      observers.forEach((o) => o.disconnect());
      const nav = performance.getEntriesByType("navigation")[0];
      const groups = {};
      performance.getEntriesByType("resource").forEach((r) => {
        let host;
        try { host = new URL(r.name).hostname; } catch { return; }
        if (host === location.hostname) return;
        const g = groups[host] || (groups[host] = { host, requests: 0, bytes: 0 });
        g.requests++;
        g.bytes += r.transferSize || 0;
      });
      resolve({
        lcp,
        cls,
        ttfb: nav ? nav.responseStart : null,
        thirdParty: Object.values(groups).sort((a, b) => b.requests - a.requests || b.bytes - a.bytes)
      });
    }, 300);
  });
}

async function scanPerformance() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) return null;
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: "MAIN",
      func: scanPagePerformance
    });
    return result || null;
  } catch {
    return null;
  }
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

  const headElements = Array.from(document.head.children).map((el) => {
    const tag = el.tagName.toLowerCase();
    const rel = (el.getAttribute("rel") || "").toLowerCase();
    const isCharset = tag === "meta" && el.hasAttribute("charset");
    const name = el.getAttribute("name") || el.getAttribute("property") || el.getAttribute("http-equiv") || "";
    const isViewport = tag === "meta" && name.toLowerCase() === "viewport";

    let content = "";
    if (tag === "meta") {
      content = isCharset ? "charset" : name;
    } else if (tag === "link") {
      content = rel + (el.getAttribute("href") ? " " + el.getAttribute("href") : "");
    } else if (tag === "script") {
      const flags = [];
      if (el.hasAttribute("async")) flags.push("async");
      if (el.hasAttribute("defer")) flags.push("defer");
      content = (flags.length ? flags.join("/") + " " : "") + (el.getAttribute("src") || "inline");
    } else if (tag === "title") {
      content = el.textContent.trim().slice(0, 80);
    } else if (tag === "style") {
      content = "inline style";
    } else {
      content = el.outerHTML.slice(0, 80);
    }

    return { tag, rel, isCharset, isViewport, content };
  });

  const jsonLd = [];
  document.querySelectorAll('script[type="application/ld+json"]').forEach((el) => {
    try {
      jsonLd.push(JSON.parse(el.textContent));
    } catch {
      // JSON inválido no bloco, ignora
    }
  });

  let favicon = null;
  for (const iconRel of ["icon", "shortcut icon", "apple-touch-icon"]) {
    const el = document.querySelector(`link[rel="${iconRel}" i]`);
    if (el && el.getAttribute("href")) {
      try {
        favicon = new URL(el.getAttribute("href"), location.href).href;
        break;
      } catch {
        // href inválido, tenta o próximo rel
      }
    }
  }
  if (!favicon) {
    favicon = new URL("/favicon.ico", location.origin).href;
  }

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
    social,
    headElements,
    jsonLd,
    favicon
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
    const positionText = "display: " + cs.display + "\nfloat: " + cs.float + "\nposition: " + cs.position + "\nz-index: " + cs.zIndex + "\nopacity: " + cs.opacity;
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

// Limiares "bom / precisa melhorar" oficiais do Core Web Vitals (TTFB: web.dev).
function vitalLabel(value, good, ok) {
  return value <= good ? "bom" : value <= ok ? "precisa melhorar" : "ruim";
}

function renderPerf(perf) {
  perfList.innerHTML = "";
  thirdPartyList.innerHTML = "";
  lastPerf = perf;
  if (!perf) {
    perfContainer.classList.add("hidden");
    thirdPartyContainer.classList.add("hidden");
    return;
  }

  const rows = [];
  if (perf.lcp !== null) rows.push(["LCP", (perf.lcp / 1000).toFixed(2) + " s (" + vitalLabel(perf.lcp, 2500, 4000) + ")"]);
  rows.push(["CLS", perf.cls.toFixed(3) + " (" + vitalLabel(perf.cls, 0.1, 0.25) + ")"]);
  if (perf.ttfb) rows.push(["TTFB", Math.round(perf.ttfb) + " ms (" + vitalLabel(perf.ttfb, 800, 1800) + ")"]);
  rows.forEach(([label, value]) => addKvRow(perfList, label, value));
  perfContainer.classList.remove("hidden");

  const total = perf.thirdParty.reduce((n, g) => n + g.requests, 0);
  if (total === 0) {
    thirdPartyContainer.classList.add("hidden");
    return;
  }
  addKvRow(thirdPartyList, "Total", total + " requisições em " + perf.thirdParty.length + " domínios");
  perf.thirdParty.slice(0, 10).forEach((g) => {
    addKvRow(thirdPartyList, g.host, g.requests + " req" + (g.bytes ? " · " + (g.bytes / 1024).toFixed(0) + " KB" : ""));
  });
  thirdPartyContainer.classList.remove("hidden");
}

function renderSecurity(checks) {
  securityList.innerHTML = "";
  lastSecurityChecks = checks;
  updateSecurityGrade();

  checks.forEach((item) => {
    const li = document.createElement("li");
    const optional = item.penalty === 0 && !item.ok;
    li.className = "severity-" + (item.ok ? "info" : optional ? "info" : "warning");

    const row = document.createElement("div");
    row.className = "link-row";

    const label = document.createElement("span");
    label.textContent = item.label;

    const badge = document.createElement("span");
    if (item.ok) {
      badge.className = "badge badge-ok";
      badge.textContent = "OK";
    } else if (optional) {
      badge.className = "badge badge-ok";
      badge.textContent = "—";
    } else {
      badge.className = "badge badge-warn";
      badge.textContent = "Ausente";
    }

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
  updateToolbarBadge();
}

function renderWpComponents(components) {
  pluginsList.innerHTML = "";
  lastWpPlugins = components.plugins || [];
  lastWpThemes = components.themes || [];
  if (!lastWpPlugins.length && !lastWpThemes.length) {
    pluginsContainer.classList.add("hidden");
    return;
  }
  lastWpThemes.forEach((t) => {
    const li = document.createElement("li");
    li.className = "severity-info";
    const row = document.createElement("div");
    row.className = "link-row";
    const span = document.createElement("span");
    span.textContent = "Tema: " + t;
    const badge = document.createElement("span");
    badge.className = "badge badge-ok";
    badge.textContent = "theme";
    row.appendChild(span);
    row.appendChild(badge);
    li.appendChild(row);
    pluginsList.appendChild(li);
  });
  lastWpPlugins.forEach((p) => {
    const li = document.createElement("li");
    li.className = "severity-info";
    const row = document.createElement("div");
    row.className = "link-row";
    const span = document.createElement("span");
    span.textContent = p;
    const badge = document.createElement("span");
    badge.className = "badge badge-ok";
    badge.textContent = "plugin";
    row.appendChild(span);
    row.appendChild(badge);
    li.appendChild(row);
    pluginsList.appendChild(li);
  });
  pluginsContainer.classList.remove("hidden");
}

function renderMixedContent(urls) {
  mixedList.innerHTML = "";
  lastMixedContent = urls || [];
  if (!lastMixedContent.length) {
    mixedContainer.classList.add("hidden");
    return;
  }
  lastMixedContent.forEach((url) => {
    const li = document.createElement("li");
    li.className = "severity-warning";
    const row = document.createElement("div");
    row.className = "link-row";
    const a = document.createElement("a");
    a.href = url;
    a.textContent = url;
    a.title = url;
    a.addEventListener("click", (e) => {
      e.preventDefault();
      openInBackground(url);
    });
    const badge = document.createElement("span");
    badge.className = "badge badge-warn";
    badge.textContent = "http";
    row.appendChild(a);
    row.appendChild(badge);
    const risk = document.createElement("div");
    risk.className = "risk-note";
    risk.textContent = "Recurso carregado via http:// em página https (mixed content).";
    li.appendChild(row);
    li.appendChild(risk);
    mixedList.appendChild(li);
  });
  mixedContainer.classList.remove("hidden");
}

function renderRobots(robots) {
  robotsList.innerHTML = "";
  lastRobots = robots;
  if (!robots) {
    robotsContainer.classList.add("hidden");
    return;
  }
  const add = (label, value) => addKvRow(robotsList, label, value);
  add("Disallow (total)", String(robots.disallowTotal));
  add("Allow (total)", String(robots.allowTotal));
  if (robots.host) add("Host", robots.host);
  if (robots.crawlDelay !== null) add("Crawl-delay", String(robots.crawlDelay));
  robots.agents.forEach((a) => {
    add(
      "User-agent: " + a.name,
      `${a.disallow.length} disallow, ${a.allow.length} allow` +
        (a.crawlDelay !== null ? `, delay ${a.crawlDelay}s` : "")
    );
  });
  if (!robots.hasDisallow && robots.agents.length === 0) {
    add("Status", "robots.txt presente, sem regras de Disallow/User-agent");
  }
  robotsContainer.classList.remove("hidden");
}

function renderEmailDns(data) {
  dnsList.innerHTML = "";
  lastEmailDns = data;
  if (!data) {
    dnsContainer.classList.add("hidden");
    return;
  }
  addKvRow(dnsList, "MX", data.mx.length ? data.mx.join(", ") : null, "Ausente");
  addKvRow(
    dnsList,
    "SPF",
    data.spf ? (data.spf.length > 80 ? data.spf.slice(0, 80) + "…" : data.spf) : null,
    "Ausente"
  );
  addKvRow(dnsList, "DMARC", data.dmarc || null, "Ausente (_dmarc)");
  addKvRow(
    dnsList,
    "Status",
    data.hasMx && data.hasSpf && data.hasDmarc
      ? "Completo (MX + SPF + DMARC)"
      : !data.hasMx
        ? "Sem MX — não recebe e-mail"
        : !data.hasSpf
          ? "Sem SPF — risco de spoofing"
          : "Sem DMARC — sem política anti-spoofing"
  );
  dnsContainer.classList.remove("hidden");
}

function renderIntegrations(list) {
  integrationsList.innerHTML = "";
  lastIntegrations = list || [];
  if (!lastIntegrations.length) {
    integrationsContainer.classList.add("hidden");
    return;
  }
  const li = document.createElement("li");
  lastIntegrations.forEach((item) => {
    const badge = document.createElement("span");
    badge.className = "tracker-badge";
    badge.textContent = item.cat ? item.cat + ": " + item.name : item.name;
    li.appendChild(badge);
  });
  integrationsList.appendChild(li);
  integrationsContainer.classList.remove("hidden");
}

function renderContact(data) {
  contactList.innerHTML = "";
  lastContact = data;
  if (!data || (!data.emails.length && !data.privacy.length)) {
    contactContainer.classList.add("hidden");
    return;
  }
  addKvRow(
    contactList,
    "E-mails na página",
    data.emails.length ? data.emails.join(", ") : null,
    "Nenhum encontrado"
  );
  data.privacy.forEach((p) => {
    const li = document.createElement("li");
    li.className = "kv-row";
    const labelEl = document.createElement("span");
    labelEl.className = "kv-label";
    labelEl.textContent = "Política / termos";
    const valueEl = document.createElement("span");
    valueEl.className = "kv-value";
    const a = document.createElement("a");
    a.href = p.href;
    a.textContent = p.text.slice(0, 60);
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    valueEl.appendChild(a);
    li.appendChild(labelEl);
    li.appendChild(valueEl);
    contactList.appendChild(li);
  });
  if (!data.privacy.length) {
    addKvRow(contactList, "Política / LGPD", null, "Nenhum link encontrado");
  }
  contactContainer.classList.remove("hidden");
}

function renderAiInfo(info) {
  aiList.innerHTML = "";
  lastAiInfo = info;
  if (!info || (!info.aiBots.length && !info.llms.present)) {
    aiContainer.classList.add("hidden");
    return;
  }
  if (info.aiBots.length) {
    info.aiBots.forEach((b) => {
      addKvRow(aiList, "Bot: " + b.name, b.blocked ? "Bloqueado (Disallow /)" : "Permitido");
    });
  } else {
    addKvRow(aiList, "Bots de IA no robots", null, "Nenhum conhecido listado");
  }
  if (info.llms.present) {
    addKvRow(
      aiList,
      "llms.txt",
      info.llms.title
        ? `Presente (${info.llms.lines} linhas) — ${info.llms.title}`
        : `Presente (${info.llms.lines} linhas)`
    );
  } else {
    addKvRow(aiList, "llms.txt", null, "Ausente em /llms.txt");
  }
  aiContainer.classList.remove("hidden");
}

function renderPageSpeed(data) {
  pagespeedList.innerHTML = "";
  lastPageSpeed = data;
  if (!data) {
    pagespeedContainer.classList.add("hidden");
    return;
  }
  ["mobile", "desktop"].forEach((strategy) => {
    const s = data[strategy];
    if (!s) return;
    if (s.error) {
      addKvRow(pagespeedList, strategy, "Erro: " + s.error);
      return;
    }
    const score = s.score !== null && s.score !== undefined ? Math.round(s.score * 100) + "/100" : "—";
    addKvRow(pagespeedList, strategy === "mobile" ? "Mobile" : "Desktop", score);
    if (s.fcp) addKvRow(pagespeedList, "  FCP", (s.fcp / 1000).toFixed(2) + " s");
    if (s.lcp) addKvRow(pagespeedList, "  LCP", (s.lcp / 1000).toFixed(2) + " s");
    if (s.cls !== null && s.cls !== undefined) addKvRow(pagespeedList, "  CLS", s.cls.toFixed(3));
    if (s.tbt !== null && s.tbt !== undefined) addKvRow(pagespeedList, "  TBT", Math.round(s.tbt) + " ms");
  });
  pagespeedContainer.classList.remove("hidden");
}

async function runPageSpeed() {
  if (!lastOrigin) return;
  const original = runPagespeedBtn.textContent;
  runPagespeedBtn.disabled = true;
  runPagespeedBtn.textContent = "⏳ Rodando PageSpeed (10–30s)...";
  pagespeedList.innerHTML = "";
  pagespeedContainer.classList.remove("hidden");

  const strategies = ["mobile", "desktop"];
  const results = {};

  await Promise.all(
    strategies.map(async (strategy) => {
      try {
        const url =
          "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=" +
          encodeURIComponent(lastOrigin) +
          "&strategy=" +
          strategy;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 45000);
        let res;
        try {
          res = await fetch(url, { signal: controller.signal });
        } finally {
          clearTimeout(timer);
        }
        if (!res.ok) {
          const err = await res.json().catch(() => null);
          results[strategy] = {
            error:
              (err && err.error && err.error.message) ||
              "HTTP " + res.status
          };
          return;
        }
        const data = await res.json();
        const lh = (data.lighthouseResult && data.lighthouseResult.audits) || {};
        const cat =
          (data.lighthouseResult &&
            data.lighthouseResult.categories &&
            data.lighthouseResult.categories.performance) ||
          {};
        const m = (id) => (lh[id] && lh[id].numericValue) || null;
        results[strategy] = {
          score: typeof cat.score === "number" ? cat.score : null,
          fcp: m("first-contentful-paint"),
          lcp: m("largest-contentful-paint"),
          cls: lh["cumulative-layout-shift"]
            ? lh["cumulative-layout-shift"].numericValue
            : null,
          tbt: m("total-blocking-time")
        };
      } catch (e) {
        results[strategy] = {
          error: e && e.name === "AbortError" ? "timeout (45s)" : "falha de rede"
        };
      }
    })
  );

  renderPageSpeed(results);
  runPagespeedBtn.disabled = false;
  runPagespeedBtn.textContent = original;
}

// Badge na toolbar: nº de achados críticos+atenção sem abrir o painel.
async function updateToolbarBadge() {
  try {
    const critical =
      lastSensitiveFiles.filter((f) => f.severity === "critical").length +
      lastFoundResults.filter((r) => r.severity === "critical").length;
    const warning =
      lastSensitiveFiles.filter((f) => f.severity === "warning").length +
      lastFoundResults.filter((r) => r.severity === "warning").length +
      lastMixedContent.length;
    const total = critical + warning;
    if (total > 0) {
      await chrome.action.setBadgeText({ text: String(Math.min(total, 99)) });
      await chrome.action.setBadgeBackgroundColor({
        color: critical > 0 ? "#ff4d5e" : "#ffcc4d"
      });
    } else {
      await chrome.action.setBadgeText({ text: "" });
    }
  } catch {}
}

// Histórico por origem em chrome.storage.local (persiste entre sessões).
async function saveHistory(origin) {
  try {
    const key = "sitexray-history:" + origin;
    const grade = computeSecurityGrade();
    const entry = {
      ts: Date.now(),
      grade: grade ? grade.grade : null,
      score: grade ? grade.score : null,
      isWordPress: lastIsWordPress,
      tech: lastTechStack.slice(0, 8),
      critical:
        lastSensitiveFiles.filter((f) => f.severity === "critical").length +
        lastFoundResults.filter((r) => r.severity === "critical").length,
      mixed: lastMixedContent.length,
      title: lastSeoData ? lastSeoData.title || "" : ""
    };
    const stored = (await chrome.storage.local.get(key))[key] || [];
    const last = stored[0];
    // Side panel refaz o scan a cada navegação: não enche o histórico
    // com a mesma nota em menos de 2 minutos.
    if (
      last &&
      Date.now() - last.ts < 120000 &&
      last.grade === entry.grade &&
      last.score === entry.score &&
      last.isWordPress === entry.isWordPress &&
      last.critical === entry.critical &&
      last.mixed === entry.mixed
    ) {
      return;
    }
    stored.unshift(entry);
    await chrome.storage.local.set({ [key]: stored.slice(0, 20) });
  } catch {}
}

async function loadHistory(origin) {
  try {
    const key = "sitexray-history:" + origin;
    const list = (await chrome.storage.local.get(key))[key] || [];
    historyList.innerHTML = "";
    if (!list.length) {
      historyContainer.classList.add("hidden");
      return;
    }
    list.forEach((e) => {
      const li = document.createElement("li");
      li.className = "severity-info";
      const row = document.createElement("div");
      row.className = "link-row";
      const when = document.createElement("span");
      when.textContent = new Date(e.ts).toLocaleString("pt-BR");
      const badge = document.createElement("span");
      if (e.grade === "A" || e.grade === "B") badge.className = "badge badge-ok";
      else if (e.grade) badge.className = "badge badge-warn";
      else badge.className = "badge badge-ok";
      badge.textContent = e.grade ? e.grade + (e.score != null ? " " + e.score : "") : "—";
      row.appendChild(when);
      row.appendChild(badge);
      const meta = document.createElement("div");
      meta.className = "risk-note";
      const bits = [];
      if (e.isWordPress) bits.push("WP");
      if (e.critical) bits.push(e.critical + " crítico(s)");
      if (e.mixed) bits.push(e.mixed + " mixed");
      if (e.tech && e.tech.length) bits.push(e.tech.slice(0, 4).join(", "));
      meta.textContent = bits.join(" · ") || (e.title ? e.title.slice(0, 80) : "");
      li.appendChild(row);
      li.appendChild(meta);
      historyList.appendChild(li);
    });
    historyContainer.classList.remove("hidden");
  } catch {
    historyContainer.classList.add("hidden");
  }
}

function addEmptyItem(list, text) {
  const li = document.createElement("li");
  li.className = "empty-state";
  li.textContent = text;
  list.appendChild(li);
}

function renderSensitiveFiles(found) {
  sensitiveList.innerHTML = "";
  lastSensitiveFiles = found;
  updateSecurityGrade();

  if (found.length === 0) {
    addEmptyItem(sensitiveList, "Nenhum arquivo sensível encontrado nos caminhos testados.");
    return;
  }

  found.forEach((f) => {
    const li = document.createElement("li");
    li.className = "severity-" + f.severity;

    const row = document.createElement("div");
    row.className = "link-row";

    const a = document.createElement("a");
    a.href = f.url;
    a.textContent = f.label;
    a.title = f.url;
    a.addEventListener("click", (e) => {
      e.preventDefault();
      openInBackground(f.url);
    });

    const badge = document.createElement("span");
    badge.className = "badge badge-warn";
    badge.textContent = SEVERITY_LABEL[f.severity];

    row.appendChild(a);
    row.appendChild(badge);

    const risk = document.createElement("div");
    risk.className = "risk-note";
    risk.textContent = f.risk;

    li.appendChild(row);
    li.appendChild(risk);
    sensitiveList.appendChild(li);
  });
}

function renderCookies(cookies) {
  cookiesList.innerHTML = "";
  lastCookies = cookies;
  updateSecurityGrade();

  if (cookies.length === 0) {
    addEmptyItem(cookiesList, "Nenhum cookie encontrado (ou sem permissão pra ler).");
    return;
  }

  cookies.forEach((c) => {
    const sameSiteOk = c.sameSite === "lax" || c.sameSite === "strict";
    const hasIssue = !c.secure || !sameSiteOk;

    const li = document.createElement("li");
    li.className = "severity-" + (hasIssue ? "warning" : "info");

    const row = document.createElement("div");
    row.className = "link-row";

    const name = document.createElement("span");
    name.textContent = c.name;

    const badgeGroup = document.createElement("span");
    badgeGroup.className = "badge-group";
    [
      ["Secure", c.secure],
      ["HttpOnly", c.httpOnly],
      ["SameSite=" + c.sameSite, sameSiteOk]
    ].forEach(([label, ok]) => {
      const badge = document.createElement("span");
      badge.className = "badge " + (ok ? "badge-ok" : "badge-warn");
      badge.textContent = label;
      badgeGroup.appendChild(badge);
    });

    row.appendChild(name);
    row.appendChild(badgeGroup);
    li.appendChild(row);
    cookiesList.appendChild(li);
  });
}

function renderRedirectCandidates(found) {
  redirectsList.innerHTML = "";
  lastRedirectCandidates = found;

  if (found.length === 0) {
    addEmptyItem(redirectsList, "Nenhum parâmetro de redirect encontrado nos links internos da página.");
    return;
  }

  found.forEach((r) => {
    const li = document.createElement("li");
    li.className = "severity-warning";

    const row = document.createElement("div");
    row.className = "link-row";

    const a = document.createElement("a");
    a.href = r.href;
    a.textContent = r.href;
    a.title = r.href;
    a.addEventListener("click", (e) => {
      e.preventDefault();
      openInBackground(r.href);
    });

    row.appendChild(a);

    const note = document.createElement("div");
    note.className = "risk-note";
    note.textContent = "Parâmetro: " + r.param;

    li.appendChild(row);
    li.appendChild(note);
    redirectsList.appendChild(li);
  });
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
    row.className = "seo-image-row";

    const thumb = document.createElement("img");
    thumb.className = "seo-image-thumb";
    thumb.src = img.src || "";
    thumb.alt = "";
    thumb.loading = "lazy";
    thumb.addEventListener("error", () => {
      thumb.style.visibility = "hidden";
    });

    const info = document.createElement("div");
    info.className = "seo-image-info";

    const nameLink = document.createElement("a");
    nameLink.className = "seo-image-link";
    nameLink.href = img.src || "#";
    nameLink.textContent = (img.src || "").split("/").pop() || img.src || "(sem src)";
    nameLink.title = img.src || "";
    nameLink.addEventListener("click", (e) => {
      e.preventDefault();
      if (img.src) openInBackground(img.src);
    });

    const alt = document.createElement("div");
    alt.className = "risk-note";
    alt.textContent = "ALT: " + (img.alt || "ausente");

    const title = document.createElement("div");
    title.className = "risk-note";
    title.textContent = "Title: " + (img.title || "ausente");

    info.appendChild(nameLink);
    info.appendChild(alt);
    info.appendChild(title);

    row.appendChild(thumb);
    row.appendChild(info);
    li.appendChild(row);

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

function renderFavicon(faviconUrl) {
  seoFaviconDownloadBtn.disabled = true;
  seoFaviconImg.style.visibility = "hidden";
  if (!faviconUrl) return;

  seoFaviconImg.onload = () => {
    seoFaviconImg.style.visibility = "visible";
    seoFaviconDownloadBtn.disabled = false;
  };
  seoFaviconImg.onerror = () => {
    seoFaviconImg.style.visibility = "hidden";
    seoFaviconDownloadBtn.disabled = true;
  };
  seoFaviconImg.src = faviconUrl;
}

function renderSeoHeadTable(elements) {
  seoHeadTbody.innerHTML = "";
  if (!elements || elements.length === 0) return;

  let sawStylesheetOrScript = false;

  elements.forEach((el, i) => {
    const tr = document.createElement("tr");

    const tagTd = document.createElement("td");
    tagTd.className = "head-tag-badge";
    tagTd.textContent = el.tag.toUpperCase();

    const contentTd = document.createElement("td");
    contentTd.textContent = el.content;

    const priority = el.isCharset || el.isViewport ? 100 : el.tag === "title" ? 95 : el.rel === "preload" ? 30 : el.rel === "stylesheet" ? 40 : el.tag === "script" ? 70 : 50;
    const priorityTd = document.createElement("td");
    priorityTd.textContent = String(priority);

    const warnTd = document.createElement("td");
    warnTd.className = "head-warning";
    const warnings = [];
    if (el.isCharset && i !== 0) warnings.push("essa tag deveria ser a 1ª do <head>");
    if (el.isViewport && sawStylesheetOrScript) warnings.push("essa tag deveria estar acima");
    if (el.tag === "title" && sawStylesheetOrScript) warnings.push("essa tag deveria estar acima");
    warnTd.textContent = warnings.join("; ");

    if (el.rel === "stylesheet" || el.tag === "script") sawStylesheetOrScript = true;

    tr.appendChild(tagTd);
    tr.appendChild(contentTd);
    tr.appendChild(priorityTd);
    tr.appendChild(warnTd);
    seoHeadTbody.appendChild(tr);
  });
}

// Anda pela árvore de um objeto JSON-LD mostrando @type + name (ou headline)
// de cada nó, recursivamente, tipo o mainEntity de uma FAQPage.
function renderJsonLdNode(obj, container, depth) {
  if (Array.isArray(obj)) {
    obj.forEach((item) => renderJsonLdNode(item, container, depth));
    return;
  }
  if (!obj || typeof obj !== "object") return;

  const type = obj["@type"];
  const label = obj.name || obj.headline || null;
  let nextDepth = depth;

  if (type) {
    const line = document.createElement("div");
    line.className = "jsonld-line";
    line.style.paddingLeft = depth * 14 + "px";

    const typeTag = document.createElement("span");
    typeTag.className = "jsonld-type";
    typeTag.textContent = "@type: " + type;
    line.appendChild(typeTag);

    if (label) {
      const nameSpan = document.createElement("span");
      nameSpan.className = "jsonld-name";
      nameSpan.textContent = " " + label;
      line.appendChild(nameSpan);
    }

    container.appendChild(line);
    nextDepth = depth + 1;
  }

  Object.keys(obj).forEach((key) => {
    if (key === "@type" || key === "@context" || key === "name" || key === "headline") return;
    const val = obj[key];
    if (Array.isArray(val) || (val && typeof val === "object")) {
      renderJsonLdNode(val, container, nextDepth);
    }
  });
}

function renderSeoJsonLd(schemas) {
  seoJsonldList.innerHTML = "";

  if (!schemas || schemas.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Nenhum dado estruturado (JSON-LD) encontrado.";
    seoJsonldList.appendChild(empty);
    return;
  }

  schemas.forEach((schema, i) => {
    const block = document.createElement("div");
    block.className = "jsonld-block";

    const header = document.createElement("div");
    header.className = "jsonld-block-header";

    const title = document.createElement("span");
    title.textContent = "Schema " + (i + 1) + (schema["@type"] ? " (" + schema["@type"] + ")" : "");

    const copyBtn = document.createElement("button");
    copyBtn.className = "open-all-btn";
    copyBtn.textContent = "Copiar JSON";
    const json = JSON.stringify(schema, null, 2);
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(json).then(() => {
        copyBtn.textContent = "Copiado!";
        setTimeout(() => { copyBtn.textContent = "Copiar JSON"; }, 1200);
      });
    });

    header.appendChild(title);
    header.appendChild(copyBtn);
    block.appendChild(header);

    const tree = document.createElement("div");
    tree.className = "jsonld-tree";
    renderJsonLdNode(schema, tree, 0);
    block.appendChild(tree);

    seoJsonldList.appendChild(block);
  });
}

function renderSeo(data) {
  lastSeoData = data;
  renderSeoSummary(data);
  renderSeoHeaders(data ? data.headings : []);
  renderSeoImages(data ? data.images : []);
  renderSeoLinks(data ? data.links : []);
  renderSeoSocial(data ? data.social : []);
  renderFavicon(data ? data.favicon : null);
  renderSeoHeadTable(data ? data.headElements : []);
  renderSeoJsonLd(data ? data.jsonLd : []);
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

function subdomainUrl(name) {
  return "https://" + name.replace(/^\*\./, "");
}

// crt.sh é um serviço público de logs de certificado transparency, sem
// autenticação e sem custo. Cobre bem "quais subdomínios esse domínio tem",
// alternativa gratuita a serviços pagos tipo Censys.
// Retorna null quando a consulta falhou (crt.sh indisponível, timeout, JSON
// inválido) e [] quando a consulta funcionou mas não achou nada, pra a UI
// não confundir "serviço fora do ar" com "domínio sem subdomínio".
async function discoverSubdomains(hostname) {
  try {
    const res = await fetchWithTimeout("https://crt.sh/?q=" + encodeURIComponent("%." + hostname) + "&output=json");
    if (!res.ok) return null;
    const data = await res.json().catch(() => null);
    if (!Array.isArray(data)) return null;

    const names = new Set();
    data.forEach((entry) => {
      (entry.name_value || "").split("\n").forEach((raw) => {
        const clean = raw.trim().toLowerCase();
        if (clean && (clean === hostname || clean.endsWith("." + hostname))) {
          names.add(clean);
        }
      });
    });

    return [...names].sort();
  } catch {
    return null;
  }
}

function renderSubdomains(names) {
  subdomainsList.innerHTML = "";
  lastSubdomains = names || [];

  if (names === null) {
    subdomainsContainer.classList.add("hidden");
    subdomainsEmpty.textContent = "Não foi possível consultar o crt.sh agora (serviço instável ou fora do ar). Tenta escanear de novo em alguns minutos.";
    subdomainsEmpty.classList.remove("hidden");
    return;
  }

  if (lastSubdomains.length === 0) {
    subdomainsContainer.classList.add("hidden");
    subdomainsEmpty.textContent = "Nenhum subdomínio encontrado via crt.sh.";
    subdomainsEmpty.classList.remove("hidden");
    return;
  }

  lastSubdomains.slice(0, SUBDOMAIN_DISPLAY_CAP).forEach((name) => {
    const li = document.createElement("li");
    li.className = "severity-info";

    const row = document.createElement("div");
    row.className = "link-row";

    const a = document.createElement("a");
    const url = subdomainUrl(name);
    a.href = url;
    a.textContent = name;
    a.title = url;
    a.addEventListener("click", (e) => {
      e.preventDefault();
      openInBackground(url);
    });

    row.appendChild(a);
    li.appendChild(row);
    subdomainsList.appendChild(li);
  });

  if (lastSubdomains.length > SUBDOMAIN_DISPLAY_CAP) {
    const note = document.createElement("li");
    note.className = "empty-state";
    note.textContent = `Mostrando ${SUBDOMAIN_DISPLAY_CAP} de ${lastSubdomains.length} encontrados.`;
    subdomainsList.appendChild(note);
  }

  subdomainsContainer.classList.remove("hidden");
  subdomainsEmpty.classList.add("hidden");
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

  if (lastWpPlugins.length || lastWpThemes.length) {
    lines.push("");
    if (lastWpThemes.length) lines.push("Tema(s) WordPress: " + lastWpThemes.join(", "));
    if (lastWpPlugins.length) lines.push("Plugins WordPress: " + lastWpPlugins.join(", "));
  }

  if (lastMixedContent.length) {
    lines.push("");
    lines.push(`Mixed content (${lastMixedContent.length}):`);
    lastMixedContent.forEach((u) => lines.push(`- ${u}`));
  }

  if (lastRobots) {
    lines.push("");
    lines.push(
      `robots.txt: ${lastRobots.disallowTotal} disallow, ${lastRobots.allowTotal} allow` +
        (lastRobots.host ? `, Host: ${lastRobots.host}` : "") +
        (lastRobots.crawlDelay !== null ? `, crawl-delay ${lastRobots.crawlDelay}s` : "")
    );
  }

  if (lastPageSpeed) {
    lines.push("");
    lines.push("PageSpeed Insights:");
    ["mobile", "desktop"].forEach((strategy) => {
      const s = lastPageSpeed[strategy];
      if (!s) return;
      if (s.error) {
        lines.push(`- ${strategy}: erro (${s.error})`);
        return;
      }
      const score = s.score != null ? Math.round(s.score * 100) + "/100" : "—";
      let line = `- ${strategy}: ${score}`;
      if (s.lcp) line += `, LCP ${(s.lcp / 1000).toFixed(2)}s`;
      if (s.cls != null) line += `, CLS ${s.cls.toFixed(3)}`;
      lines.push(line);
    });
  }

  lines.push("");
  lines.push(
    lastTrackers.length > 0
      ? `Rastreadores/pixels: ${lastTrackers.join(", ")}`
      : "Rastreadores/pixels: nenhum encontrado"
  );

  if (lastPerf) {
    lines.push("");
    lines.push("Performance (Web Vitals):");
    if (lastPerf.lcp !== null) lines.push(`- LCP: ${(lastPerf.lcp / 1000).toFixed(2)} s (${vitalLabel(lastPerf.lcp, 2500, 4000)})`);
    lines.push(`- CLS: ${lastPerf.cls.toFixed(3)} (${vitalLabel(lastPerf.cls, 0.1, 0.25)})`);
    if (lastPerf.ttfb) lines.push(`- TTFB: ${Math.round(lastPerf.ttfb)} ms (${vitalLabel(lastPerf.ttfb, 800, 1800)})`);
    const thirdTotal = lastPerf.thirdParty.reduce((n, g) => n + g.requests, 0);
    lines.push(`- Requisições de terceiros: ${thirdTotal} em ${lastPerf.thirdParty.length} domínios`);
  }

  lines.push("");
  const grade = computeSecurityGrade();
  if (grade) {
    lines.push(`Nota de segurança: ${grade.grade} (${grade.score}/100)`);
    lines.push("");
  }
  lines.push("Segurança:");
  lastSecurityChecks.forEach((item) => {
    const optional = item.penalty === 0 && !item.ok;
    lines.push(`- [${item.ok ? "OK" : optional ? "—" : "Ausente"}] ${item.label} - ${item.note}`);
  });

  if (lastSensitiveFiles.length > 0) {
    lines.push("Arquivos sensíveis expostos:");
    lastSensitiveFiles.forEach((f) => lines.push(`- [${SEVERITY_LABEL[f.severity]}] ${f.label} - ${f.risk}`));
  } else {
    lines.push("Arquivos sensíveis expostos: nenhum encontrado nos caminhos testados");
  }

  const weakCookies = lastCookies.filter((c) => !c.secure || !(c.sameSite === "lax" || c.sameSite === "strict"));
  lines.push(`Cookies: ${lastCookies.length} encontrado(s), ${weakCookies.length} sem Secure ou SameSite adequado`);
  weakCookies.forEach((c) => lines.push(`- ${c.name} (Secure=${c.secure}, HttpOnly=${c.httpOnly}, SameSite=${c.sameSite})`));

  if (lastRedirectCandidates.length > 0) {
    lines.push(`Candidatos a Open Redirect (${lastRedirectCandidates.length}, não confirmados):`);
    lastRedirectCandidates.forEach((r) => lines.push(`- ${r.href} (parâmetro ${r.param})`));
  }

  lines.push("");
  lines.push("SEO on-page:");
  if (lastSeoData) {
    const withoutAlt = lastSeoData.images.filter((img) => !img.alt).length;
    lines.push(`- Title: ${lastSeoData.title || "ausente"} (${(lastSeoData.title || "").length} caracteres)`);
    lines.push(`- Description: ${lastSeoData.description ? lastSeoData.description.length + " caracteres" : "ausente"}`);
    lines.push(`- Canonical: ${lastSeoData.canonical || "ausente"}`);
    lines.push(`- Favicon: ${lastSeoData.favicon || "não encontrado"}`);
    lines.push(`- Dados estruturados (JSON-LD): ${lastSeoData.jsonLd.length} bloco(s)`);
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

  lines.push("");
  if (lastSubdomains.length > 0) {
    lines.push(`Subdomínios encontrados via crt.sh (${lastSubdomains.length}):`);
    lastSubdomains.forEach((name) => lines.push(`- ${name}`));
  } else {
    lines.push("Subdomínios: nenhum encontrado via crt.sh");
  }

  if (lastEmailDns) {
    lines.push("");
    lines.push("E-mail / DNS:");
    lines.push(`- MX: ${lastEmailDns.mx.length ? lastEmailDns.mx.join(", ") : "ausente"}`);
    lines.push(`- SPF: ${lastEmailDns.spf || "ausente"}`);
    lines.push(`- DMARC: ${lastEmailDns.dmarc || "ausente"}`);
  }

  if (lastIntegrations.length) {
    lines.push("");
    lines.push("Integrações: " + lastIntegrations.map((i) => i.name).join(", "));
  }

  if (lastContact && (lastContact.emails.length || lastContact.privacy.length)) {
    lines.push("");
    if (lastContact.emails.length) lines.push("E-mails na página: " + lastContact.emails.join(", "));
    if (lastContact.privacy.length) {
      lines.push("Política/termos:");
      lastContact.privacy.forEach((p) => lines.push(`- ${p.text} (${p.href})`));
    }
  }

  if (lastAiInfo && (lastAiInfo.aiBots.length || lastAiInfo.llms.present)) {
    lines.push("");
    lines.push("IA / llms.txt:");
    lastAiInfo.aiBots.forEach((b) => lines.push(`- ${b.name}: ${b.blocked ? "bloqueado" : "permitido"}`));
    if (lastAiInfo.llms.present) lines.push(`- llms.txt: presente (${lastAiInfo.llms.lines} linhas)`);
    else lines.push("- llms.txt: ausente");
  }

  return lines.join("\n");
}

const cacheKey = (origin) => "sitexray:" + origin;

// Cache por origem em chrome.storage.session: some ao fechar o navegador,
// então não precisa de limpeza. Falha (cota, contexto sem acesso) é ignorada.
async function saveCache(origin) {
  try {
    await chrome.storage.session.set({
      [cacheKey(origin)]: {
        ts: Date.now(),
        trackers: lastTrackers, tech: lastTechStack, security: lastSecurityChecks,
        sensitive: lastSensitiveFiles, cookies: lastCookies, redirects: lastRedirectCandidates,
        seo: lastSeoData, sitemaps: lastSitemapResults, subdomains: lastSubdomains,
        perf: lastPerf, isWordPress: lastIsWordPress, wpLinks: lastFoundResults,
        plugins: lastWpPlugins, themes: lastWpThemes, mixed: lastMixedContent,
        robots: lastRobots, pageSpeed: lastPageSpeed,
        emailDns: lastEmailDns, integrations: lastIntegrations,
        contact: lastContact, ai: lastAiInfo
      }
    });
  } catch {}
}

// Mostra o último resultado da origem na hora; o scan real sobrescreve em seguida.
async function restoreCache(origin) {
  try {
    const key = cacheKey(origin);
    const c = (await chrome.storage.session.get(key))[key];
    if (!c || Date.now() - c.ts > CACHE_TTL_MS) return 0;
    renderTrackers(c.trackers);
    renderTech(c.tech);
    if (c.security.length) renderSecurity(c.security);
    renderSensitiveFiles(c.sensitive);
    renderCookies(c.cookies);
    renderRedirectCandidates(c.redirects);
    if (c.seo) renderSeo(c.seo);
    if (c.sitemaps.length) renderSitemapList(c.sitemaps);
    if (c.subdomains.length) renderSubdomains(c.subdomains);
    renderPerf(c.perf);
    lastIsWordPress = c.isWordPress;
    if (c.plugins) renderWpComponents({ plugins: c.plugins, themes: c.themes || [] });
    if (c.mixed) renderMixedContent(c.mixed);
    if (c.robots) renderRobots(c.robots);
    if (c.pageSpeed) renderPageSpeed(c.pageSpeed);
    if (c.emailDns) renderEmailDns(c.emailDns);
    if (c.integrations && c.integrations.length) renderIntegrations(c.integrations);
    if (c.contact) renderContact(c.contact);
    if (c.ai) renderAiInfo(c.ai);
    if (c.isWordPress && c.wpLinks.length) renderLinks(c.wpLinks);
    loadHistory(origin);
    return Math.max(1, Math.round((Date.now() - c.ts) / 60000));
  } catch {
    return 0;
  }
}

async function runScan() {
  const id = ++scanId;
  const current = () => id === scanId;
  const guard = (fn) => (v) => { if (current()) fn(v); };

  statusEl.className = "status status-checking";
  statusEl.textContent = "Verificando o site...";
  perfContainer.classList.add("hidden");
  thirdPartyContainer.classList.add("hidden");
  linksContainer.classList.add("hidden");
  sitemapContainer.classList.add("hidden");
  sitemapEmpty.classList.add("hidden");
  subdomainsContainer.classList.add("hidden");
  subdomainsEmpty.classList.add("hidden");
  trackersContainer.classList.add("hidden");
  techContainer.classList.add("hidden");
  integrationsContainer.classList.add("hidden");
  contactContainer.classList.add("hidden");
  dnsContainer.classList.add("hidden");
  aiContainer.classList.add("hidden");
  securityContainer.classList.add("hidden");
  sensitiveList.innerHTML = "";
  cookiesList.innerHTML = "";
  redirectsList.innerHTML = "";
  pluginsContainer.classList.add("hidden");
  mixedContainer.classList.add("hidden");
  robotsContainer.classList.add("hidden");
  historyContainer.classList.add("hidden");
  pagespeedContainer.classList.add("hidden");
  lastWpPlugins = [];
  lastWpThemes = [];
  lastMixedContent = [];
  lastRobots = null;
  lastPageSpeed = null;
  lastEmailDns = null;
  lastIntegrations = [];
  lastContact = null;
  lastAiInfo = null;
  tabsEl.classList.add("hidden");
  emptyState.classList.add("hidden");
  rescanBtn.classList.add("hidden");
  copyReportBtn.classList.add("hidden");
  exportReportBtn.classList.add("hidden");
  exportHtmlBtn.classList.add("hidden");
  document.getElementById("report-actions").classList.add("hidden");
  securityGradeEl.classList.add("hidden");
  lastSecurityChecks = [];
  lastSensitiveFiles = [];
  lastCookies = [];
  try {
    await chrome.action.setBadgeText({ text: "" });
  } catch {}

  const origin = await getActiveTabOrigin();
  if (!current()) return;
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
  whoisLinkEl.href = "https://registro.br/tecnologia/ferramentas/whois?search=" + encodeURIComponent(hostname);
  dnsCheckerLinkEl.href = "https://dnschecker.org/all-dns-records-of-domain.php?query=" + encodeURIComponent(hostname + "/") + "&rtype=ALL&dns=google";
  defaultSitemapLinkEl.href = origin + "/sitemap.xml";
  googleSiteLinkEl.href = "https://www.google.com/search?q=" + encodeURIComponent("site:" + hostname);
  domainToolsEl.classList.remove("hidden");
  tabsEl.classList.remove("hidden");

  // Trackers/pixels, subdomínios e SEO on-page são verificados independente do site ser WordPress ou não.
  const cached = await restoreCache(origin);
  if (!current()) return;
  if (cached) statusEl.textContent = `Verificando o site... (mostrando resultado salvo há ${cached} min)`;

  const tasks = [
    detectTrackers().then(guard(renderTrackers)),
    discoverSubdomains(hostname).then(guard(renderSubdomains)),
    checkSensitiveFiles(origin).then(guard(renderSensitiveFiles)),
    getCookieFlags(origin).then(guard(renderCookies)),
    scanPerformance().then(guard(renderPerf)),
    lookupEmailAuth(hostname).then(guard(renderEmailDns)),
    (async () => {
      const robotsText = await fetchRobotsRaw(origin);
      const llms = await checkLlmsTxt(origin);
      return { aiBots: detectAiBots(robotsText), llms };
    })().then(guard(renderAiInfo)),
    scanSeo().then(async (data) => {
      if (!current()) return;
      renderSeo(data);
      renderRedirectCandidates(data ? findRedirectCandidates(data.links, origin) : []);
      if (data && data.links.length > 0) {
        await checkLinkStatuses(data.links, origin);
        if (current()) renderSeoLinks(data.links);
      }
    })
  ];

  const finish = async () => {
    await Promise.allSettled(tasks);
    if (!current()) return;
    await saveCache(origin);
    await saveHistory(origin);
    await updateToolbarBadge();
    loadHistory(origin);
    rescanBtn.classList.remove("hidden");
    document.getElementById("report-actions").classList.remove("hidden");
  };

  const { html: homepageHtml, headers } = await fetchHomepage(origin);
  if (!current()) return;

  // Mescla headers same-origin da página (HSTS etc. que o fetch da
  // extensão pode esconder). Prioriza o que a página viu.
  const pageHeaders = await probePageSecurityHeaders();
  if (!current()) return;
  Object.keys(pageHeaders).forEach((k) => {
    if (pageHeaders[k] !== "") headers[k] = pageHeaders[k];
  });

  // Sitemap também é independente: roda mesmo que a detecção de WP falhe.
  tasks.push(discoverSitemaps(origin, homepageHtml).then(guard(renderSitemapList)));
  tasks.push(fetchRobotsAnalysis(origin).then(guard(renderRobots)));

  const [isWordPress, httpsForced] = await Promise.all([
    detectWordPress(origin, homepageHtml),
    checkHttpsForced(origin)
  ]);
  if (!current()) return;
  lastIsWordPress = isWordPress;

  const techStack = detectTechStack(homepageHtml, headers);
  if (isWordPress) techStack.unshift("WordPress");
  renderTech(techStack);
  renderIntegrations(detectIntegrations(homepageHtml, headers));
  renderContact(extractContactInfo(homepageHtml));
  renderSecurity(buildSecurityChecks(headers, httpsForced));
  renderMixedContent(findMixedContent(homepageHtml, origin));

  if (isWordPress) {
    renderWpComponents(detectWpComponents(homepageHtml));
  }

  if (!isWordPress) {
    statusEl.className = "status status-not-found";
    statusEl.textContent = "Este site não parece ser WordPress.";
    lastFoundResults = [];
    await finish();
    return;
  }

  statusEl.className = "status status-found";
  statusEl.textContent = "WordPress detectado. Checando links públicos...";

  const pathResults = await Promise.all(CANDIDATE_PATHS.map((entry) => checkPath(origin, entry)));
  if (!current()) return;

  statusEl.textContent = "WordPress detectado.";
  renderLinks(dedupeByUrl(pathResults));
  await finish();
}

rescanBtn.addEventListener("click", runScan);

whoisLinkEl.addEventListener("click", (e) => {
  e.preventDefault();
  openInBackground(whoisLinkEl.href);
});

dnsCheckerLinkEl.addEventListener("click", (e) => {
  e.preventDefault();
  openInBackground(dnsCheckerLinkEl.href);
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

openAllSubdomainsBtn.addEventListener("click", () => {
  lastSubdomains.slice(0, SUBDOMAIN_DISPLAY_CAP).forEach((name) => openInBackground(subdomainUrl(name)));
});

startInspectorBtn.addEventListener("click", startInspector);

seoFaviconDownloadBtn.addEventListener("click", async () => {
  if (!lastSeoData || !lastSeoData.favicon) return;
  const original = seoFaviconDownloadBtn.textContent;
  try {
    const res = await fetchWithTimeout(lastSeoData.favicon);
    if (!res.ok) throw new Error("resposta não ok");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const extMatch = lastSeoData.favicon.split("?")[0].match(/\.([a-zA-Z0-9]{2,4})$/);
    const ext = extMatch ? extMatch[1] : "ico";

    const a = document.createElement("a");
    a.href = url;
    a.download = "favicon." + ext;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch {
    seoFaviconDownloadBtn.textContent = "Erro ao baixar";
    setTimeout(() => { seoFaviconDownloadBtn.textContent = original; }, 1500);
  }
});

devRepoLinkEl.href = REPO_URL;
devRepoLinkEl.addEventListener("click", (e) => {
  e.preventDefault();
  openInBackground(REPO_URL);
});

devBtn.addEventListener("click", () => {
  devBtn.classList.toggle("active");
  devPanel.classList.toggle("hidden");
});

let copyInFlight = false;
copyReportBtn.addEventListener("click", async () => {
  if (copyInFlight) return;
  copyInFlight = true;
  const original = copyReportBtn.textContent;
  try {
    await navigator.clipboard.writeText(buildReport());
    copyReportBtn.textContent = "✅ Copiado!";
  } catch {
    copyReportBtn.textContent = "Erro ao copiar";
  }
  setTimeout(() => {
    copyReportBtn.textContent = original;
    copyInFlight = false;
  }, 1500);
});

exportReportBtn.addEventListener("click", async () => {
  const original = exportReportBtn.textContent;
  try {
    const report = buildReport();
    const blob = new Blob([report], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const host = (lastOrigin || "site").replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]+/gi, "-");
    a.download = `sitexray-${host}-${new Date().toISOString().slice(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    exportReportBtn.textContent = "✅ Baixado!";
  } catch {
    exportReportBtn.textContent = "Erro ao baixar";
  }
  setTimeout(() => {
    exportReportBtn.textContent = original;
  }, 1500);
});

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function buildHtmlReport() {
  const grade = computeSecurityGrade();
  const logoData = await new Promise((resolve) => {
    try {
      fetch(chrome.runtime.getURL("icons/logo.png"))
        .then((r) => r.blob())
        .then((b) => {
          const fr = new FileReader();
          fr.onload = () => resolve(fr.result);
          fr.onerror = () => resolve("");
          fr.readAsDataURL(b);
        })
        .catch(() => resolve(""));
    } catch {
      resolve("");
    }
  });

  const rows = [];
  const row = (k, v) => {
    if (v != null && v !== "") rows.push(`<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(v)}</td></tr>`);
  };

  row("Data", new Date().toLocaleString("pt-BR"));
  row("URL", lastOrigin);
  row("Nota segurança", grade ? `${grade.grade} (${grade.score}/100)` : "—");
  row("WordPress", lastIsWordPress ? "detectado" : "não detectado");
  row("Tecnologia", lastTechStack.join(", ") || "não identificada");
  if (lastWpThemes.length) row("Tema", lastWpThemes.join(", "));
  if (lastWpPlugins.length) row("Plugins", lastWpPlugins.join(", "));
  if (lastSeoData) {
    row("Title", lastSeoData.title || "ausente");
    row("Description", lastSeoData.description ? lastSeoData.description.slice(0, 160) : "ausente");
    row("Canonical", lastSeoData.canonical || "ausente");
  }
  if (lastPerf) {
    if (lastPerf.lcp !== null) row("LCP", (lastPerf.lcp / 1000).toFixed(2) + " s");
    row("CLS", lastPerf.cls.toFixed(3));
    if (lastPerf.ttfb) row("TTFB", Math.round(lastPerf.ttfb) + " ms");
  }
  if (lastPageSpeed) {
    ["mobile", "desktop"].forEach((s) => {
      const p = lastPageSpeed[s];
      if (p && !p.error && p.score != null) row("PageSpeed " + s, Math.round(p.score * 100) + "/100");
    });
  }
  if (lastTrackers.length) row("Rastreadores", lastTrackers.join(", "));
  if (lastMixedContent.length) row("Mixed content", lastMixedContent.length + " recurso(s) http");
  if (lastIntegrations.length) row("Integrações", lastIntegrations.map((i) => i.name).join(", "));
  if (lastEmailDns) {
    row("MX", lastEmailDns.mx.join(", ") || "ausente");
    row("SPF", lastEmailDns.spf || "ausente");
    row("DMARC", lastEmailDns.dmarc || "ausente");
  }
  if (lastContact && lastContact.emails.length) row("E-mails", lastContact.emails.join(", "));

  const secRows = lastSecurityChecks
    .map((c) => {
      const optional = c.penalty === 0 && !c.ok;
      const cls = c.ok || optional ? "ok" : "bad";
      const label = c.ok ? "OK" : optional ? "—" : "Ausente";
      return `<li class="${cls}"><span>${escapeHtml(c.label)}</span><b>${label}</b></li>`;
    })
    .join("");

  const sens =
    lastSensitiveFiles.length > 0
      ? lastSensitiveFiles
          .map(
            (f) =>
              `<li class="bad"><span>${escapeHtml(f.label)}</span><b>${escapeHtml(SEVERITY_LABEL[f.severity] || f.severity)}</b></li>`
          )
          .join("")
      : `<li class="ok"><span>Arquivos sensíveis</span><b>Nenhum</b></li>`;

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relatório SiteXray - ${escapeHtml(lastOrigin)}</title>
<style>
  body{font-family:ui-monospace,Consolas,monospace;background:#0a0e12;color:#d6e4ec;margin:0;padding:32px;line-height:1.5}
  .wrap{max-width:820px;margin:0 auto}
  img.logo{height:36px;margin-bottom:16px}
  h1{font-size:20px;color:#39ff9e;margin:0 0 4px}
  .meta{color:#6f8494;font-size:13px;margin-bottom:24px}
  table{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:13px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1e2a35;vertical-align:top}
  th{color:#6f8494;width:38%;font-weight:600}
  h2{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:#6f8494;margin:28px 0 10px}
  ul{list-style:none;padding:0;margin:0}
  li{display:flex;justify-content:space-between;gap:12px;padding:8px 10px;background:#10161d;border:1px solid #1e2a35;border-radius:3px;margin-bottom:6px;font-size:13px}
  li.ok{border-left:3px solid #39ff9e}
  li.bad{border-left:3px solid #ff4d5e}
  li b{flex-shrink:0}
  .grade{display:inline-flex;align-items:center;gap:12px;padding:12px 16px;background:#10161d;border:1px solid #1e2a35;border-radius:6px;margin-bottom:20px}
  .grade span{font-size:40px;font-weight:800;color:#39ff9e}
  .grade div{font-size:13px;color:#d6e4ec}
  footer{margin-top:32px;color:#6f8494;font-size:11px}
</style>
</head>
<body>
<div class="wrap">
${logoData ? `<img class="logo" src="${logoData}" alt="SiteXray">` : ""}
<h1>Relatório SiteXray</h1>
<div class="meta">${escapeHtml(lastOrigin)} · ${new Date().toLocaleString("pt-BR")}</div>
${
  grade
    ? `<div class="grade"><span>${escapeHtml(grade.grade)}</span><div>Nota de segurança<br>${grade.score}/100</div></div>`
    : ""
}
<table>${rows.join("")}</table>
<h2>Segurança (headers)</h2>
<ul>${secRows}</ul>
<h2>Arquivos sensíveis</h2>
<ul>${sens}</ul>
<footer>Gerado por SiteXray · análise passiva, sem testes de exploração.</footer>
</div>
</body>
</html>`;
}

exportHtmlBtn.addEventListener("click", async () => {
  const original = exportHtmlBtn.textContent;
  try {
    const html = await buildHtmlReport();
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const host = (lastOrigin || "site").replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]+/gi, "-");
    a.download = `sitexray-${host}-${new Date().toISOString().slice(0, 10)}.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    exportHtmlBtn.textContent = "✅ Baixado!";
  } catch {
    exportHtmlBtn.textContent = "Erro ao baixar";
  }
  setTimeout(() => {
    exportHtmlBtn.textContent = original;
  }, 1500);
});

runPagespeedBtn.addEventListener("click", runPageSpeed);

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

document.addEventListener("DOMContentLoaded", () => {
  runScan();
  checkForUpdate();
});

// Side panel fica aberto entre abas: refaz o scan ao trocar de aba ou navegar.
let rescanTimer;
const rescanSoon = () => {
  clearTimeout(rescanTimer);
  rescanTimer = setTimeout(runScan, 400);
};
chrome.tabs.onActivated.addListener(rescanSoon);
chrome.tabs.onUpdated.addListener((_id, info, tab) => {
  if (info.status === "complete" && tab.active) rescanSoon();
});
