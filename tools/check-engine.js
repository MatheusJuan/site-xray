// Checagem do motor de tecnologias e da análise de tracking, sem navegador.
//   node tools/check-engine.js
// Baixa a base do Wappalyzer (fork enthec) como a extensão faz; sem rede, só
// roda os testes sintéticos. Falha com código 1 se qualquer asserção quebrar.
const assert = require("assert");
const path = require("path");
const ext = path.join(__dirname, "..", "wp-link-scanner");
const E = require(path.join(ext, "tech-engine.js"));
const T = require(path.join(ext, "tracking.js"));

const BASE = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/";
const FILES = "_abcdefghijklmnopqrstuvwxyz".split("");
const blank = (o = {}) => ({
  url: "https://exemplo.com.br/", html: "", scripts: "", scriptSrc: [], css: "", text: "",
  meta: {}, js: {}, dom: {}, hosts: [], headers: {}, cookies: {}, dns: {}, ...o
});
const names = (items) => items.map((i) => i.name);
const find = (items, n) => items.find((i) => i.name === n);

async function synthetic() {
  // Lógica pura em base minúscula: versão, ternário, confiança, requires, implies, excludes, wildcard.
  const db = E.compileTechDb({
    cats: { 1: { name: "CMS", priority: 1 }, 9: { name: "Analytics", priority: 9 } },
    techs: {
      Alpha: { cats: [1], scriptSrc: ["alpha-([\\d.]+)\\.js\\;version:\\1"], implies: ["Beta"] },
      Beta: { cats: [9] },
      Gamma: { cats: [9], meta: { generator: "^gamma(?: (\\d+))?\\;version:\\1?v\\1:unknown" } },
      Weak: { cats: [9], js: { weakGlobal: "\\;confidence:50" } },
      Weak2: { cats: [9], js: { w1: "\\;confidence:40" }, html: ["<w2>\\;confidence:40"] },
      Gated: { cats: [9], requires: ["Alpha"], html: ["gated-marker"] },
      GatedOff: { cats: [9], requires: ["Nope"], html: ["gated-marker"] },
      Loser: { cats: [9], html: ["loser-marker"] },
      Winner: { cats: [1], html: ["winner-marker"], excludes: ["Loser"] },
      Cookie: { cats: [9], cookies: { "_ck_*": "" } }
    }
  });

  let r = await E.runDetection(db, blank({ scriptSrc: ["/js/alpha-2.5.1.js"], html: "gated-marker loser-marker winner-marker", meta: { generator: ["Gamma 7"] }, cookies: { _ck_abc: "1" } }));
  assert.strictEqual(find(r, "Alpha").version, "2.5.1", "versão por scriptSrc");
  assert.ok(find(r, "Beta") && find(r, "Beta").implied, "implies");
  assert.strictEqual(find(r, "Gamma").version, "v7", "ternário com grupo");
  assert.ok(find(r, "Gated"), "requires atendido");
  assert.ok(!find(r, "GatedOff"), "requires não atendido");
  assert.ok(!find(r, "Loser") && find(r, "Winner"), "excludes");
  assert.ok(find(r, "Cookie"), "cookie com wildcard");
  assert.strictEqual(E.groupTechByCategory(r)[0][0], "CMS", "categoria de menor prioridade primeiro");

  r = await E.runDetection(db, blank({ meta: { generator: ["gamma"] }, js: { weakGlobal: "", w1: "" }, html: "<w2>" }));
  assert.strictEqual(find(r, "Gamma").version, "unknown", "ternário sem grupo");
  assert.strictEqual(find(r, "Weak").confidence, 50, "confiança 50 aparece com percentual");
  assert.strictEqual(find(r, "Weak2").confidence, 80, "confianças somam entre padrões distintos");
  assert.strictEqual(E.fillVersion("\\1?a:b", ["", "x"]), "a");
  assert.strictEqual(E.fillVersion("\\1?:b", ["", ""]), "b");
}

async function real() {
  let raw;
  try {
    const get = async (p) => {
      const res = await fetch(BASE + p);
      if (!res.ok) throw new Error(p);
      return res.json();
    };
    const [cats, ...parts] = await Promise.all([get("categories.json"), ...FILES.map((f) => get(`technologies/${f}.json`))]);
    const techs = {};
    parts.forEach((p) => Object.keys(p).forEach((n) => (techs[n] = E.slimTech(p[n]))));
    raw = { cats, techs };
  } catch {
    console.log("sem rede: pulando testes com a base real");
    return;
  }
  const db = E.compileTechDb(raw);
  console.log(`base real: ${db.techs.size} tecnologias, ${db.jsPaths.length} caminhos JS, ${Object.keys(db.domSpecs).length} seletores`);
  assert.ok(db.techs.size > 5000, "base carregou");

  const t0 = Date.now();
  const html = "<html><head>" + "<link rel='stylesheet' href='/wp-content/themes/x/style.css'>".repeat(5) + "</head><body>" + "<p>texto qualquer</p>".repeat(15000) + "</body></html>";
  const r = await E.runDetection(db, blank({
    html,
    scriptSrc: ["https://code.jquery.com/jquery-3.6.0.min.js", "https://connect.facebook.net/en_US/fbevents.js", "https://www.googletagmanager.com/gtag/js?id=G-ABC123XYZ9"],
    scripts: "window.dataLayer=[];gtag('config', 'G-ABC123XYZ9');",
    meta: { generator: ["WordPress 6.4.2"] },
    js: { __NEXT_DATA__: "" },
    headers: { "x-powered-by": "Next.js 14.0.1", server: "nginx/1.24.0" },
    cookies: { _ga_abc123xyz9: "GS1.1", _shopify_y: "abc" },
    dns: { MX: ["1 aspmx.l.google.com"], NS: ["ns1.cloudflare.com"] }
  }));
  console.log(`detecção em ${Date.now() - t0} ms: ${names(r).length} tecnologias`);

  assert.strictEqual(find(r, "WordPress").version, "6.4.2", "WordPress por meta generator");
  assert.ok(find(r, "PHP"), "WordPress implica PHP");
  assert.strictEqual(find(r, "jQuery").version, "3.6.0", "jQuery por scriptSrc");
  assert.ok(find(r, "Facebook Pixel"), "Meta Pixel por scriptSrc");
  assert.ok(find(r, "Google Analytics"), "GA por cookie wildcard / gtag");
  assert.ok(find(r, "Next.js") && find(r, "Next.js").version === "14.0.1", "Next.js por header e versão");
  assert.ok(find(r, "React"), "Next.js implica React");
  assert.ok(find(r, "Shopify"), "Shopify por cookie");
  assert.ok(find(r, "Nginx"), "Nginx por header Server");
  assert.ok(find(r, "Google Workspace") || find(r, "Google Apps for Business") || r.some((i) => /google/i.test(i.name) && i.cats.includes(75)), "e-mail Google por MX");
  assert.ok(find(r, "Cloudflare"), "Cloudflare por NS");
}

function tracking() {
  const raw = {
    entries: 80, bufferFull: false,
    meta: {
      hasFbq: true, libLoaded: true, libVersion: "2.9.150", noscript: false, inlineInit: true, advancedMatching: false,
      pixels: { "111222333444555": ["fbq", "request"] },
      events: [
        { id: "111222333444555", ev: "PageView", count: 2, value: false, currency: "", userData: false, eventId: false },
        { id: "111222333444555", ev: "Purchase", count: 1, value: false, currency: "", userData: false, eventId: false }
      ]
    },
    gtm: { containers: { "GTM-ABCD12": { hosts: ["www.googletagmanager.com"], noscript: false, global: true, inline: true } }, dataLayers: { dataLayer: { length: 3, events: { "gtm.js": 1, "gtm.load": 1 }, consent: null, ecommerce: false } } },
    google: {
      hasGtag: true, hasAnalyticsJs: false,
      ids: { "G-ABC123XYZ9": ["gtag.js", "request"], "UA-1234567-1": ["html"] },
      ga4: [{ tid: "G-ABC123XYZ9", en: "page_view", host: "region1.google-analytics.com", gcs: "G111", count: 2 }],
      ua: [], ads: []
    }
  };
  const view = T.analyzeTracking(raw, ["_ga", "_ga_abc123xyz9", "_fbp"]);
  const texts = [...view.meta.findings, ...view.google.findings].map((f) => f.text).join("\n");
  assert.ok(/PageView disparado 2x/.test(texts), "PageView duplicado");
  assert.ok(/Purchase sem valor/.test(texts), "Purchase sem valor");
  assert.ok(/Universal Analytics foi descontinuado/.test(texts), "UA descontinuado");
  assert.ok(/2 page_view/.test(texts), "page_view duplicado no GA4");
  assert.ok(/gtag\.js direto e GTM/.test(texts), "gtag.js + GTM");
  assert.ok(/Consent Mode não detectado/.test(texts), "sem Consent Mode");
  assert.deepStrictEqual(view.google.cookies.ga4Streams, ["G-ABC123XYZ9"], "cookie _ga_ mapeia o stream");
  assert.strictEqual(T.analyzeTracking(null, []), null);
  const empty = T.analyzeTracking({ ...raw, meta: { ...raw.meta, hasFbq: false, libLoaded: false, pixels: {}, events: [] }, google: { ...raw.google, ids: {}, ga4: [] }, gtm: { containers: {}, dataLayers: {} } }, []);
  assert.strictEqual(empty.meta.detected, false);
  assert.ok(T.trackingReportLines(view).join("\n").includes("Meta Pixel: 111222333444555"), "relatório cita o pixel");
}

(async () => {
  await synthetic();
  tracking();
  await real();
  console.log("ok");
})().catch((e) => {
  console.error(e.stack || e);
  process.exit(1);
});
