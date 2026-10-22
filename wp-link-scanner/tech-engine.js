// Motor de detecção de tecnologias, compatível com o formato de fingerprints
// do Wappalyzer (url, html, scripts, scriptSrc, meta, headers, cookies, js,
// dom, css, text, xhr, dns, implies, excludes, requires, tags de confiança e
// versão). A base de padrões vem do fork comunitário enthec/webappanalyzer
// (GPL-3.0), baixada em runtime e guardada em chrome.storage.local por 7 dias.
// Não é embutida no repositório de propósito: baixar dado em runtime evita
// redistribuir a base (GPL) junto com o código da extensão.
//
// Não suportados (poucas técnicas, precisam de infraestrutura que a
// extensão não tem): probe, robots, certIssuer.

const TECH_DB_BASE = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/";
const TECH_DB_FILES = "_abcdefghijklmnopqrstuvwxyz".split("");
const TECH_DB_KEY = "sitexray:techdb";
const TECH_DB_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const TECH_DB_RETRY_MS = 10 * 60 * 1000;
const TECH_MIN_CONFIDENCE = 50;

const TECH_CATEGORY_PT = {
  1: "CMS", 2: "Fóruns", 3: "Gerenciadores de banco de dados", 4: "Documentação", 5: "Widgets",
  6: "E-commerce", 7: "Galerias de fotos", 8: "Wikis", 9: "Painéis de hospedagem", 10: "Analytics",
  11: "Blogs", 12: "Frameworks JavaScript", 13: "Rastreadores de issues", 14: "Players de vídeo",
  15: "Sistemas de comentários", 16: "Segurança", 17: "Fontes (scripts)", 18: "Frameworks web",
  19: "Diversos", 20: "Editores", 21: "LMS", 22: "Servidores web", 23: "Cache",
  24: "Editores de texto rico", 25: "Gráficos JavaScript", 26: "Frameworks mobile",
  27: "Linguagens de programação", 28: "Sistemas operacionais", 29: "Mecanismos de busca",
  30: "Webmail", 31: "CDN", 32: "Automação de marketing", 33: "Extensões de servidor web",
  34: "Bancos de dados", 35: "Mapas", 36: "Publicidade", 37: "Dispositivos de rede",
  38: "Servidores de mídia", 39: "Webcams", 41: "Processadores de pagamento", 42: "Gerenciadores de tags",
  44: "CI", 45: "Sistemas de controle", 46: "Acesso remoto", 47: "Desenvolvimento",
  48: "Armazenamento em rede", 49: "Leitores de feed", 50: "DMS", 51: "Page builders",
  52: "Chat ao vivo", 53: "CRM", 54: "SEO", 55: "Contabilidade", 56: "Criptomineradores",
  57: "Geradores de site estático", 58: "Onboarding de usuários", 59: "Bibliotecas JavaScript",
  60: "Contêineres", 62: "PaaS", 63: "IaaS", 64: "Proxies reversos", 65: "Balanceadores de carga",
  66: "Frameworks de UI", 67: "Conformidade de cookies", 68: "Acessibilidade", 69: "Autenticação",
  70: "Autoridades certificadoras", 71: "Programas de afiliados", 72: "Agendamento", 73: "Pesquisas",
  74: "Testes A/B", 75: "E-mail", 76: "Personalização", 77: "Retargeting", 78: "RUM (monitoramento real)",
  79: "Geolocalização", 80: "Temas WordPress", 81: "Temas Shopify", 82: "Temas Drupal",
  83: "Fingerprint de navegador", 84: "Fidelidade e recompensas", 85: "Feature flags", 86: "Segmentação",
  87: "Plugins WordPress", 88: "Hospedagem", 89: "Tradução", 90: "Avaliações",
  91: "Compre agora, pague depois", 92: "Performance", 93: "Reservas e delivery", 94: "Indicação",
  95: "Gestão de ativos digitais", 96: "Curadoria de conteúdo", 97: "Plataformas de dados (CDP)",
  98: "Carrinho abandonado", 99: "Transportadoras", 100: "Apps Shopify", 101: "Recrutamento",
  102: "Devoluções", 103: "Livestreaming", 104: "Venda de ingressos", 105: "Realidade aumentada",
  106: "E-commerce internacional", 107: "Fulfillment", 108: "Frontends de e-commerce",
  109: "Domínios estacionados", 110: "Construtores de formulário", 111: "Doações",
  112: "Inteligência artificial"
};

// ---------------------------------------------------------------- padrões

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// "regex\;confidence:50\;version:\1" -> { re, confidence, version }
function parsePattern(str) {
  const [src, ...tags] = String(str).split("\\;");
  const p = { re: null, confidence: 100, version: "" };
  for (const tag of tags) {
    const i = tag.indexOf(":");
    if (i < 0) continue;
    const key = tag.slice(0, i);
    const val = tag.slice(i + 1);
    if (key === "confidence") p.confidence = parseInt(val, 10) || 100;
    else if (key === "version") p.version = val;
  }
  try {
    p.re = new RegExp(src, "i");
  } catch {
    return null;
  }
  return p;
}

// \1 devolve o grupo 1; \1?a:b é condicional (a se o grupo existe, senão b).
function fillVersion(tpl, m) {
  const v = tpl
    .replace(/\\(\d)\?([^:]*):(.*)$/, (_, i, a, b) => (m[+i] ? a : b))
    .replace(/\\(\d)/g, (_, i) => m[+i] || "")
    .trim();
  return v.length > 24 ? "" : v;
}

const toPatterns = (list) => [].concat(list == null ? [] : list).map(parsePattern).filter(Boolean);

function patternMap(obj, lowerKeys) {
  const out = {};
  Object.keys(obj || {}).forEach((k) => {
    const ps = toPatterns(obj[k]);
    if (ps.length) out[lowerKeys ? k.toLowerCase() : k] = ps;
  });
  return out;
}

function compileDom(dom) {
  const out = {};
  if (Array.isArray(dom)) {
    dom.forEach((sel) => {
      out[sel] = { exists: toPatterns([""]), attributes: {}, properties: {}, text: [] };
    });
  } else {
    Object.keys(dom || {}).forEach((sel) => {
      const d = dom[sel] || {};
      out[sel] = {
        exists: d.exists !== undefined ? toPatterns([d.exists]) : [],
        attributes: patternMap(d.attributes),
        properties: patternMap(d.properties),
        text: d.text !== undefined ? toPatterns([d.text]) : []
      };
    });
  }
  return out;
}

function compileCookies(obj) {
  const out = {};
  Object.keys(obj || {}).forEach((k) => {
    const ps = toPatterns(obj[k]);
    if (!ps.length) return;
    const key = k.toLowerCase();
    out[key] = {
      ps,
      keyRe: key.includes("*") ? new RegExp("^" + escapeRegExp(key).replace(/\\\*/g, ".*") + "$") : null
    };
  });
  return out;
}

function parseRefs(list) {
  return (list || []).map((s) => {
    const [name, ...tags] = String(s).split("\\;");
    const tag = tags.find((t) => t.startsWith("confidence:"));
    return { name, confidence: tag ? parseInt(tag.slice(11), 10) || 100 : 100 };
  });
}

// Guarda só o que a detecção usa (descrição, preço, CPE etc. ficam de fora
// pra caber folgado no storage).
const TECH_KEEP = [
  "cats", "website", "icon", "implies", "excludes", "requires", "requiresCategory",
  "url", "xhr", "text", "html", "scripts", "scriptSrc", "css", "meta", "headers",
  "cookies", "js", "dom", "dns"
];

function slimTech(t) {
  const out = {};
  TECH_KEEP.forEach((k) => {
    if (t && t[k] !== undefined) out[k] = t[k];
  });
  return out;
}

function compileTechDb(raw) {
  const techs = new Map();
  const jsPaths = new Set();
  const domSpecs = {};

  Object.keys(raw.techs).forEach((name) => {
    const t = raw.techs[name];
    if (!t || typeof t !== "object") return;
    try {
      const c = {
        name,
        cats: t.cats || [],
        website: t.website || "",
        icon: t.icon || "",
        implies: parseRefs(t.implies),
        excludes: (t.excludes || []).map((s) => String(s).split("\\;")[0]),
        requires: t.requires || [],
        requiresCategory: t.requiresCategory || [],
        url: toPatterns(t.url),
        xhr: toPatterns(t.xhr),
        text: toPatterns(t.text),
        html: toPatterns(t.html),
        scripts: toPatterns(t.scripts),
        scriptSrc: toPatterns(t.scriptSrc),
        css: toPatterns(t.css),
        meta: patternMap(t.meta, true),
        headers: patternMap(t.headers, true),
        cookies: compileCookies(t.cookies),
        js: patternMap(t.js),
        dom: compileDom(t.dom),
        dns: patternMap(t.dns)
      };
      Object.keys(c.js).forEach((p) => jsPaths.add(p));
      Object.keys(c.dom).forEach((sel) => {
        const spec = (domSpecs[sel] = domSpecs[sel] || [new Set(), new Set(), false]);
        Object.keys(c.dom[sel].attributes).forEach((a) => spec[0].add(a));
        Object.keys(c.dom[sel].properties).forEach((p) => spec[1].add(p));
        if (c.dom[sel].text.length) spec[2] = true;
      });
      techs.set(name, c);
    } catch {
      // Entrada malformada na base: ignora só ela.
    }
  });

  const specs = {};
  Object.keys(domSpecs).forEach((sel) => {
    specs[sel] = [[...domSpecs[sel][0]], [...domSpecs[sel][1]], domSpecs[sel][2]];
  });
  return { techs, cats: raw.cats || {}, jsPaths: [...jsPaths], domSpecs: specs };
}

// ------------------------------------------------------------- carga da base

let techDbMemo = null;
let techDbInflight = null;
let techDbFailedAt = 0;

async function fetchTechDb() {
  const get = async (path) => {
    const res = await fetchWithTimeout(TECH_DB_BASE + path);
    if (!res.ok) throw new Error(path);
    return res.json();
  };
  const [cats, ...parts] = await Promise.all([
    get("categories.json"),
    ...TECH_DB_FILES.map((f) => get(`technologies/${f}.json`))
  ]);
  const techs = {};
  parts.forEach((part) => {
    Object.keys(part).forEach((name) => {
      techs[name] = slimTech(part[name]);
    });
  });
  return { ts: Date.now(), cats, techs };
}

async function loadTechDbUncached() {
  let stored = null;
  try {
    stored = (await chrome.storage.local.get(TECH_DB_KEY))[TECH_DB_KEY] || null;
  } catch {}
  if (stored && Date.now() - stored.ts < TECH_DB_TTL_MS) return compileTechDb(stored);

  if (Date.now() - techDbFailedAt > TECH_DB_RETRY_MS) {
    try {
      const fresh = await fetchTechDb();
      try {
        await chrome.storage.local.set({ [TECH_DB_KEY]: fresh });
      } catch {}
      return compileTechDb(fresh);
    } catch {
      techDbFailedAt = Date.now();
    }
  }
  // Sem rede: usa a cópia vencida, melhor que nada. Sem cópia: null.
  return stored ? compileTechDb(stored) : null;
}

function loadTechDb() {
  if (techDbMemo) return Promise.resolve(techDbMemo);
  if (!techDbInflight) {
    techDbInflight = loadTechDbUncached()
      .then((db) => {
        techDbMemo = db;
        return db;
      })
      .finally(() => {
        techDbInflight = null;
      });
  }
  return techDbInflight;
}

// ----------------------------------------------------------------- detecção

const yieldUi = () => new Promise((r) => setTimeout(r, 0));

function categoryOf(cats, catTable) {
  let best = null;
  cats.forEach((id) => {
    const pr = catTable[id] ? catTable[id].priority : 99;
    if (best === null || pr < best.pr) best = { id, pr };
  });
  return best || { id: 19, pr: 10 };
}

// S: { url, html, scripts, scriptSrc[], css, text, meta{}, js{}, dom{},
// hosts[], headers{}, cookies{}, dns{} }. Chaves de meta/headers/cookies em
// minúsculas, de dns em maiúsculas.
async function runDetection(db, S, forceNames = []) {
  const found = new Map();

  const hit = (name, key, confidence, version) => {
    let f = found.get(name);
    if (!f) found.set(name, (f = { conf: new Map(), versions: [] }));
    f.conf.set(key, confidence);
    if (version) f.versions.push({ v: version, c: confidence });
  };

  const test = (name, kind, key, patterns, value) => {
    if (value == null) return;
    for (const p of patterns) {
      const m = p.re.exec(value);
      if (m) hit(name, `${kind}:${key}:${p.re.source}`, p.confidence, p.version ? fillVersion(p.version, m) : "");
    }
  };

  const analyze = (t) => {
    const n = t.name;
    if (t.url.length) test(n, "url", "", t.url, S.url);
    if (t.xhr.length) S.hosts.forEach((h) => test(n, "xhr", "", t.xhr, h));
    if (t.text.length) test(n, "text", "", t.text, S.text);
    if (t.html.length) test(n, "html", "", t.html, S.html);
    if (t.scripts.length) test(n, "scripts", "", t.scripts, S.scripts);
    if (t.css.length) test(n, "css", "", t.css, S.css);
    if (t.scriptSrc.length) S.scriptSrc.forEach((src) => test(n, "scriptSrc", "", t.scriptSrc, src));
    for (const k in t.meta) (S.meta[k] || []).forEach((v) => test(n, "meta", k, t.meta[k], v));
    for (const k in t.headers) test(n, "headers", k, t.headers[k], S.headers[k]);
    for (const k in t.cookies) {
      const c = t.cookies[k];
      if (c.keyRe) {
        for (const cn in S.cookies) if (c.keyRe.test(cn)) test(n, "cookies", cn, c.ps, S.cookies[cn]);
      } else if (k in S.cookies) {
        test(n, "cookies", k, c.ps, S.cookies[k]);
      }
    }
    for (const path in t.js) if (path in S.js) test(n, "js", path, t.js[path], S.js[path]);
    for (const sel in t.dom) {
      const r = S.dom[sel];
      if (!r) continue;
      const d = t.dom[sel];
      if (d.exists.length) test(n, "dom", sel + "|exists", d.exists, "");
      for (const a in d.attributes) (r.attrs[a] || []).forEach((v) => test(n, "dom", `${sel}|@${a}`, d.attributes[a], v));
      for (const p in d.properties) (r.props[p] || []).forEach((v) => test(n, "dom", `${sel}|.${p}`, d.properties[p], v));
      if (d.text.length) r.text.forEach((v) => test(n, "dom", sel + "|text", d.text, v));
    }
    for (const type in t.dns) (S.dns[type] || []).forEach((v) => test(n, "dns", type, t.dns[type], v));
  };

  const all = [...db.techs.values()];
  const plain = all.filter((t) => !t.requires.length && !t.requiresCategory.length);
  const gated = all.filter((t) => t.requires.length || t.requiresCategory.length);

  for (let i = 0; i < plain.length; i++) {
    analyze(plain[i]);
    if (i % 500 === 499) await yieldUi();
  }

  // Técnicas com "requires" só rodam depois que a exigida foi encontrada;
  // repete até estabilizar (uma exigida pode depender de outra).
  const done = new Set();
  const catsOfFound = () => {
    const ids = new Set();
    found.forEach((_, name) => (db.techs.get(name).cats || []).forEach((c) => ids.add(c)));
    return ids;
  };
  for (let round = 0, changed = true; changed && round < 4; round++) {
    changed = false;
    const ids = catsOfFound();
    for (const t of gated) {
      if (done.has(t.name)) continue;
      const okName = !t.requires.length || t.requires.some((r) => found.has(r));
      const okCat = !t.requiresCategory.length || t.requiresCategory.some((c) => ids.has(c));
      if (!okName || !okCat) continue;
      done.add(t.name);
      analyze(t);
      if (found.has(t.name)) changed = true;
    }
  }

  forceNames.forEach((n) => {
    if (db.techs.has(n)) hit(n, "external:", 100, "");
  });

  // implies: A implica B (com a confiança declarada), em cadeia.
  const queue = [...found.keys()];
  for (let i = 0; i < queue.length; i++) {
    db.techs.get(queue[i]).implies.forEach(({ name, confidence }) => {
      if (!db.techs.has(name)) return;
      const isNew = !found.has(name);
      hit(name, "implies:" + queue[i], confidence, "");
      if (isNew) queue.push(name);
    });
  }

  // excludes: A exclui B mesmo que B tenha sido detectada.
  [...found.keys()].forEach((name) => {
    db.techs.get(name).excludes.forEach((x) => found.delete(x));
  });

  const items = [];
  found.forEach((f, name) => {
    const confidence = Math.min(100, [...f.conf.values()].reduce((a, b) => a + b, 0));
    if (confidence < TECH_MIN_CONFIDENCE) return;
    const t = db.techs.get(name);
    const cat = categoryOf(t.cats, db.cats);
    const best = f.versions.sort((a, b) => b.c - a.c || b.v.length - a.v.length)[0];
    items.push({
      name,
      version: best ? best.v : "",
      confidence,
      cats: t.cats,
      catName: TECH_CATEGORY_PT[cat.id] || (db.cats[cat.id] && db.cats[cat.id].name) || "Outros",
      catPriority: cat.pr,
      website: t.website,
      icon: t.icon,
      implied: [...f.conf.keys()].every((k) => k.startsWith("implies:"))
    });
  });
  return items;
}

// Lista antiga de nomes (assinaturas próprias) no mesmo formato de itens,
// usada quando a base do Wappalyzer não pôde ser carregada.
function legacyTechItems(names) {
  return (names || []).map((name) => ({
    name, version: "", confidence: 100, cats: [], catName: "Tecnologias",
    catPriority: 99, website: "", icon: "", implied: false
  }));
}

const techLabel = (it) => it.name + (it.version ? " " + it.version : "");

// [[categoria, itens[]]] ordenado por prioridade da categoria, depois nome.
function groupTechByCategory(items) {
  const groups = new Map();
  items.forEach((it) => {
    if (!groups.has(it.catName)) groups.set(it.catName, { priority: it.catPriority, items: [] });
    groups.get(it.catName).items.push(it);
  });
  return [...groups.entries()]
    .sort((a, b) => a[1].priority - b[1].priority || a[0].localeCompare(b[0], "pt"))
    .map(([name, g]) => [name, g.items.sort((a, b) => a.name.localeCompare(b.name))]);
}

// ------------------------------------------------------ coleta (página/rede)

// Injetada na página (world MAIN): 100% autocontida. Lê só o necessário pra
// os padrões da base: HTML renderizado, scripts, meta, globais JS e seletores.
function collectTechSignalsInPage(jsPaths, domSpecs) {
  const cap = (s, n) => (s.length > n ? s.slice(0, n / 2) + s.slice(-n / 2) : s);
  const out = { url: location.href, html: "", scripts: "", scriptSrc: [], css: "", text: "", meta: {}, js: {}, dom: {}, hosts: [] };
  try {
    out.html = cap(document.documentElement.outerHTML, 400000);
  } catch {}
  const inline = [];
  document.querySelectorAll("script").forEach((s) => {
    if (s.src) out.scriptSrc.push(s.src);
    else if (s.textContent) inline.push(s.textContent);
  });
  out.scripts = cap(inline.join("\n"), 200000);
  out.css = cap(Array.from(document.querySelectorAll("style")).map((s) => s.textContent || "").join("\n"), 100000);
  out.text = cap((document.body && document.body.innerText) || "", 50000);
  document.querySelectorAll("meta").forEach((m) => {
    const k = (m.getAttribute("name") || m.getAttribute("property") || "").toLowerCase();
    const v = m.getAttribute("content");
    if (k && v != null) (out.meta[k] = out.meta[k] || []).push(v);
  });

  jsPaths.forEach((path) => {
    try {
      let v = window;
      for (const part of path.split(".")) {
        if (v === undefined || v === null) return;
        v = v[part];
      }
      if (v === undefined || v === null) return;
      out.js[path] = typeof v === "string" || typeof v === "number" || typeof v === "boolean" ? String(v).slice(0, 100) : "";
    } catch {}
  });

  Object.keys(domSpecs).forEach((sel) => {
    let els;
    try {
      els = document.querySelectorAll(sel);
    } catch {
      return;
    }
    if (!els.length) return;
    const [attrs, props, wantText] = domSpecs[sel];
    const r = { attrs: {}, props: {}, text: [] };
    Array.from(els).slice(0, 25).forEach((el) => {
      attrs.forEach((a) => {
        const v = el.getAttribute(a);
        if (v != null) (r.attrs[a] = r.attrs[a] || []).push(v.slice(0, 300));
      });
      props.forEach((p) => {
        const v = el[p];
        if (v === undefined || v === null) return;
        (r.props[p] = r.props[p] || []).push(typeof v === "object" || typeof v === "function" ? "" : String(v).slice(0, 300));
      });
      if (wantText) r.text.push((el.textContent || "").slice(0, 500));
    });
    out.dom[sel] = r;
  });

  // Hosts contatados (aproxima o "xhr" do Wappalyzer, que usa só XHR/fetch).
  const hosts = new Set();
  performance.getEntriesByType("resource").forEach((e) => {
    try {
      hosts.add(new URL(e.name).hostname);
    } catch {}
  });
  out.hosts = [...hosts].slice(0, 300);
  return out;
}

async function collectTechSignals(db) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) return null;
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: "MAIN",
      func: collectTechSignalsInPage,
      args: [db.jsPaths, db.domSpecs]
    });
    return result || null;
  } catch {
    return null;
  }
}

// Valores só em memória, pra casar padrões de cookie; nunca guardados.
async function getDetectionCookies(origin) {
  const out = {};
  try {
    (await chrome.cookies.getAll({ url: origin })).forEach((c) => {
      out[c.name.toLowerCase()] = c.value;
    });
  } catch {}
  return out;
}

// Registros que a base usa (MX, TXT, NS, SOA, CNAME) via DNS-over-HTTPS.
async function fetchTechDns(hostname) {
  const types = ["MX", "TXT", "NS", "SOA", "CNAME"];
  const out = {};
  await Promise.all(
    types.map(async (type) => {
      const data = await dohQuery(hostname, type);
      out[type] = (data && Array.isArray(data.Answer) ? data.Answer : [])
        .map((a) => String(a.data || "").replace(/^"|"$/g, ""))
        .filter(Boolean);
    })
  );
  return out;
}

// Ponto de entrada: retorna itens, ou null se a base não está disponível.
async function detectTechnologies({ origin, hostname, headers, homepageHtml, forceNames }) {
  try {
    const db = await loadTechDb();
    if (!db) return null;
    const [signals, cookies, dns] = await Promise.all([
      collectTechSignals(db),
      getDetectionCookies(origin),
      fetchTechDns(hostname)
    ]);
    // Página que bloqueia injeção (ex: Chrome Web Store): cai pro HTML baixado.
    const S = signals || {
      url: origin + "/", html: homepageHtml || "", scripts: "", scriptSrc: [],
      css: "", text: "", meta: {}, js: {}, dom: {}, hosts: []
    };
    return await runDetection(db, { ...S, headers: headers || {}, cookies, dns }, forceNames || []);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- interface

function techItemEl(it) {
  const a = document.createElement("a");
  a.className = "tech-item" + (it.implied ? " tech-implied" : "");
  const site = /^https?:\/\//i.test(it.website) ? it.website : "";
  a.href = site || "#";
  a.title = it.implied ? "Inferida a partir de outra tecnologia" : it.website || it.name;
  a.addEventListener("click", (e) => {
    e.preventDefault();
    if (site) openInBackground(site);
  });

  if (it.icon) {
    const img = document.createElement("img");
    img.className = "tech-icon";
    img.alt = "";
    img.loading = "lazy";
    img.referrerPolicy = "no-referrer";
    img.src = TECH_DB_BASE + "images/icons/" + encodeURIComponent(it.icon);
    img.addEventListener("error", () => img.remove());
    a.appendChild(img);
  }

  const name = document.createElement("span");
  name.className = "tech-name";
  name.textContent = it.name;
  a.appendChild(name);

  if (it.version) {
    const v = document.createElement("span");
    v.className = "tech-version";
    v.textContent = it.version;
    a.appendChild(v);
  }
  if (it.confidence < 100) {
    const c = document.createElement("span");
    c.className = "tech-conf";
    c.textContent = it.confidence + "%";
    c.title = "Confiança da detecção";
    a.appendChild(c);
  }
  return a;
}

function drawTechGroups(root, items) {
  root.innerHTML = "";
  groupTechByCategory(items).forEach(([cat, list]) => {
    const group = document.createElement("div");
    group.className = "tech-group";
    const title = document.createElement("div");
    title.className = "tech-group-title";
    title.textContent = cat;
    group.appendChild(title);
    const grid = document.createElement("div");
    grid.className = "tech-grid";
    list.forEach((it) => grid.appendChild(techItemEl(it)));
    group.appendChild(grid);
    root.appendChild(group);
  });
}

if (typeof module !== "undefined") {
  module.exports = { parsePattern, fillVersion, compileTechDb, runDetection, groupTechByCategory, techLabel, slimTech };
}
