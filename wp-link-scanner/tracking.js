// Visão detalhada de Meta Pixel, Google Tag Manager, GA4/Universal Analytics e
// Google Ads. Tudo passivo: lê o que a página já carregou (DOM, globais,
// dataLayer e as requisições que ela já fez, via Resource Timing).
//
// Limites reais: o buffer de Resource Timing guarda 250 requisições, então em
// página pesada os disparos tardios podem faltar (o diagnóstico avisa); só
// aparece o que já aconteceu até o scan; eventos em lote (POST) do GA4 não
// expõem o nome do evento na URL.

const TRACKING_DELAY_MS = 1200;
const META_CONVERSION_EVENTS = ["Purchase", "Lead", "CompleteRegistration", "InitiateCheckout", "AddToCart", "Subscribe", "Contact", "SubmitApplication", "StartTrial", "Schedule"];
const GOOGLE_HOST_RE = /(^|\.)(google-analytics\.com|analytics\.google\.com|google\.com|googletagmanager\.com|doubleclick\.net|googleadservices\.com)$/i;

// Injetada na página (world MAIN): 100% autocontida. Devolve só dados crus,
// a análise fica no painel. Nunca devolve valores do dataLayer, só nomes de
// eventos e o estado de consentimento (granted/denied).
function scanTrackingInPage() {
  const out = {
    entries: 0,
    bufferFull: false,
    meta: { hasFbq: false, libLoaded: false, libVersion: "", noscript: false, inlineInit: false, advancedMatching: false, pixels: {}, events: [] },
    gtm: { containers: {}, dataLayers: {} },
    google: { hasGtag: false, hasAnalyticsJs: false, ids: {}, ga4: [], ua: [], ads: [] }
  };
  const safeUrl = (u) => {
    try {
      return new URL(u, location.href);
    } catch {
      return null;
    }
  };
  const addSrc = (map, id, src) => {
    const list = (map[id] = map[id] || []);
    if (!list.includes(src)) list.push(src);
  };
  const bump = (list, keyFn, make) => {
    const key = keyFn;
    let item = list.find((x) => x._k === key);
    if (!item) {
      item = make();
      item._k = key;
      list.push(item);
    }
    item.count++;
    return item;
  };

  const scripts = Array.from(document.scripts);
  const srcs = scripts.map((s) => s.src).filter(Boolean);
  const inline = scripts.filter((s) => !s.src).map((s) => s.textContent || "").join("\n").slice(0, 600000);
  const noscripts = Array.from(document.querySelectorAll("noscript")).map((n) => n.textContent || "").join("\n");
  const res = performance.getEntriesByType("resource").map((e) => e.name);
  out.entries = res.length;
  out.bufferFull = res.length >= 250;
  const urls = srcs.concat(res);

  // ---- Meta Pixel
  const m = out.meta;
  const fbIds = m.pixels;
  if (typeof window.fbq === "function") {
    m.hasFbq = true;
    m.libVersion = String(window.fbq.version || "");
    try {
      const st = typeof window.fbq.getState === "function" ? window.fbq.getState() : null;
      ((st && st.pixels) || []).forEach((p) => {
        if (!p || !p.id) return;
        addSrc(fbIds, String(p.id), "fbq");
        if (p.userData && Object.keys(p.userData).length) m.advancedMatching = true;
      });
    } catch {}
    try {
      Object.keys((window.fbq.instance && window.fbq.instance.pixelsByID) || {}).forEach((id) => addSrc(fbIds, id, "fbq"));
    } catch {}
  }
  for (const x of inline.matchAll(/fbq\(\s*['"]init['"]\s*,\s*['"]?(\d{6,20})['"]?(\s*,\s*\{)?/g)) {
    m.inlineInit = true;
    addSrc(fbIds, x[1], "html");
    if (x[2]) m.advancedMatching = true;
  }
  for (const x of noscripts.matchAll(/facebook\.com\/tr\?[^"'\s]*?\bid=(\d{6,20})/g)) {
    m.noscript = true;
    addSrc(fbIds, x[1], "noscript");
  }
  urls.forEach((u) => {
    if (/connect\.facebook\.net\/[^/]+\/(fbevents|events)\.js/.test(u)) m.libLoaded = true;
    const cfg = u.match(/connect\.facebook\.net\/signals\/config\/(\d{6,20})/);
    if (cfg) addSrc(fbIds, cfg[1], "config");
  });
  res.forEach((u) => {
    if (!/^https?:\/\/(www\.)?facebook\.com\/tr\/?\?/.test(u)) return;
    const url = safeUrl(u);
    if (!url) return;
    const q = url.searchParams;
    const id = q.get("id") || "";
    const ev = q.get("ev") || "?";
    if (id) addSrc(fbIds, id, "request");
    const e = bump(m.events, id + "|" + ev, () => ({ id, ev, count: 0, value: false, currency: "", userData: false, eventId: false }));
    if (q.has("cd[value]")) e.value = true;
    if (q.get("cd[currency]")) e.currency = q.get("cd[currency]").slice(0, 8);
    if (q.has("eid")) e.eventId = true;
    for (const key of q.keys()) if (key.startsWith("ud[")) e.userData = true;
  });

  // ---- Google Tag Manager
  const gtm = out.gtm;
  const container = (id) => (gtm.containers[id] = gtm.containers[id] || { hosts: [], noscript: false, global: false, inline: false });
  const dlNames = new Set(["dataLayer"]);
  urls.forEach((u) => {
    if (!/\/gtm\.js\?/.test(u)) return;
    const url = safeUrl(u);
    const id = url && (url.searchParams.get("id") || "");
    if (!id || !/^GTM-/i.test(id)) return;
    const c = container(id.toUpperCase());
    if (!c.hosts.includes(url.hostname)) c.hosts.push(url.hostname);
    const l = url.searchParams.get("l");
    if (l) dlNames.add(l);
  });
  const nsText = noscripts + "\n" + Array.from(document.querySelectorAll('iframe[src*="googletagmanager.com/ns.html"]')).map((f) => f.src).join("\n");
  for (const x of nsText.matchAll(/googletagmanager\.com\/ns\.html\?id=(GTM-[A-Z0-9]+)/gi)) container(x[1].toUpperCase()).noscript = true;
  for (const x of inline.matchAll(/\bGTM-[A-Z0-9]{4,10}\b/g)) container(x[0]).inline = true;

  const gIds = out.google.ids;
  try {
    const rt = window.google_tag_manager;
    if (rt && typeof rt === "object") {
      Object.keys(rt).forEach((k) => {
        if (/^GTM-/.test(k)) container(k).global = true;
        else if (/^(G|UA|AW|DC|GT)-/.test(k)) addSrc(gIds, k, "gtm-runtime");
      });
    }
  } catch {}

  dlNames.forEach((name) => {
    let dl;
    try {
      dl = window[name];
    } catch {
      return;
    }
    if (!Array.isArray(dl)) return;
    const info = { length: dl.length, events: {}, consent: null, ecommerce: false };
    dl.slice(0, 1000).forEach((entry) => {
      try {
        if (!entry || typeof entry !== "object") return;
        if (typeof entry.length === "number" && typeof entry[0] === "string") {
          // Chamadas gtag(): ficam no dataLayer como objetos "arguments".
          if (entry[0] === "event" && typeof entry[1] === "string") info.events[entry[1]] = (info.events[entry[1]] || 0) + 1;
          else if (entry[0] === "consent" && (entry[1] === "default" || entry[1] === "update") && entry[2] && typeof entry[2] === "object") {
            info.consent = info.consent || { default: null, update: null };
            const state = {};
            Object.keys(entry[2]).forEach((k) => {
              if (entry[2][k] === "granted" || entry[2][k] === "denied") state[k] = entry[2][k];
            });
            info.consent[entry[1]] = state;
          }
        } else {
          if (typeof entry.event === "string") info.events[entry.event] = (info.events[entry.event] || 0) + 1;
          if (entry.ecommerce) info.ecommerce = true;
        }
      } catch {}
    });
    gtm.dataLayers[name] = info;
  });

  // ---- Google Analytics / Google tag / Ads
  const g = out.google;
  g.hasGtag = typeof window.gtag === "function";
  g.hasAnalyticsJs = typeof window.ga === "function";
  try {
    if (g.hasAnalyticsJs && typeof window.ga.getAll === "function") {
      window.ga.getAll().forEach((t) => {
        const id = t && t.get && t.get("trackingId");
        if (id) addSrc(gIds, String(id).toUpperCase(), "analytics.js");
      });
    }
  } catch {}
  urls.forEach((u) => {
    if (!/\/gtag\/js\?/.test(u)) return;
    const url = safeUrl(u);
    const id = url && (url.searchParams.get("id") || "");
    if (id && /^(G|UA|AW|DC|GT)-/i.test(id)) addSrc(gIds, id.toUpperCase(), "gtag.js");
  });
  for (const x of inline.matchAll(/gtag\([^)]{0,300}?['"]((?:G|AW|DC|GT)-[A-Z0-9]{6,14}|UA-\d{4,10}-\d{1,3})(?:\/([\w-]+))?['"]/g)) addSrc(gIds, x[1], "html");
  for (const x of inline.matchAll(/(?:measurementId|trackingId|tracking_id|gaProperty)['"]?\s*[:=]\s*['"]((?:G|UA)-[A-Z0-9-]+)['"]/g)) addSrc(gIds, x[1], "html");

  res.forEach((u) => {
    const url = safeUrl(u);
    if (!url) return;
    const q = url.searchParams;
    const p = url.pathname;
    if (/\/g\/collect$/.test(p) || (/\/collect$/.test(p) && q.get("v") === "2")) {
      const tid = q.get("tid") || "";
      const e = bump(g.ga4, tid + "|" + (q.get("en") || ""), () => ({ tid, en: q.get("en") || "", host: url.hostname, gcs: q.get("gcs") || "", count: 0 }));
      if (tid) addSrc(gIds, tid, "request");
      return e;
    }
    if (/\/(r\/|j\/)?collect$/.test(p) && q.get("v") === "1") {
      const tid = q.get("tid") || "";
      bump(g.ua, tid + "|" + (q.get("t") || ""), () => ({ tid, t: q.get("t") || "", count: 0 }));
      if (tid) addSrc(gIds, tid, "request");
      return;
    }
    const conv =
      (/(^|\.)googleadservices\.com$/.test(url.hostname) && p.match(/^\/pagead\/conversion\/(\d+)\//)) ||
      (/(^|\.)google\.com$/.test(url.hostname) && p.match(/^\/pagead\/1p-conversion\/(\d+)\//)) ||
      (/(^|\.)doubleclick\.net$/.test(url.hostname) && p.match(/^\/pagead\/viewthroughconversion\/(\d+)\//));
    if (conv) {
      const label = q.get("label") || "";
      bump(g.ads, conv[1] + "|" + label, () => ({ id: "AW-" + conv[1], label, count: 0 }));
      addSrc(gIds, "AW-" + conv[1], "request");
    }
  });

  [m.events, g.ga4, g.ua, g.ads].forEach((list) => list.forEach((x) => delete x._k));
  return out;
}

async function collectTracking(delayMs) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) return null;
    // Dá tempo dos pixels dispararem depois do load antes de ler.
    if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: "MAIN",
      func: scanTrackingInPage
    });
    return result || null;
  } catch {
    return null;
  }
}

// ----------------------------------------------------------------- análise

function tagKind(id) {
  if (id.startsWith("G-")) return "GA4 / Google tag";
  if (id.startsWith("UA-")) return "Universal Analytics";
  if (id.startsWith("AW-")) return "Google Ads";
  if (id.startsWith("DC-")) return "Floodlight";
  if (id.startsWith("GT-")) return "Google tag";
  return "Google";
}

// Transforma o cru da página em modelo de exibição + diagnóstico.
// cookieNames: nomes (minúsculos) dos cookies do site.
function analyzeTracking(raw, cookieNames) {
  if (!raw) return null;
  const hasCookie = (n) => cookieNames.includes(n);
  const byCount = (a, b) => b.count - a.count;

  // ----- Meta
  const mr = raw.meta;
  const pixels = Object.keys(mr.pixels).map((id) => ({ id, sources: mr.pixels[id] }));
  const metaDetected = mr.hasFbq || mr.libLoaded || pixels.length > 0 || mr.noscript;
  const events = mr.events.slice().sort(byCount);
  const meta = {
    detected: metaDetected,
    pixels,
    events,
    libVersion: mr.libVersion,
    noscript: mr.noscript,
    inlineInit: mr.inlineInit,
    advancedMatching: mr.advancedMatching,
    cookies: { _fbp: hasCookie("_fbp"), _fbc: hasCookie("_fbc") },
    findings: []
  };
  const mf = meta.findings;
  if (metaDetected) {
    if (!pixels.length) mf.push({ level: "warn", text: "A biblioteca do Pixel carregou, mas nenhum Pixel ID foi encontrado (fbq('init') ausente?)." });
    if (!events.length) {
      mf.push({
        level: raw.bufferFull ? "info" : "warn",
        text: raw.bufferFull
          ? "Nenhum evento visto, mas o buffer de requisições da página encheu (250): disparos tardios podem não aparecer."
          : "Nenhum evento observado: o PageView pode não estar disparando, ou o pixel espera o aceite de cookies."
      });
    } else if (!events.some((e) => e.ev === "PageView")) {
      mf.push({ level: "warn", text: "Eventos disparados, mas sem PageView: confira a instalação base do Pixel." });
    }
    if (pixels.length > 1) mf.push({ level: "info", text: `${pixels.length} Pixel IDs na mesma página: confirme que são intencionais (pixel duplicado infla conversões).` });
    events.filter((e) => e.ev === "PageView" && e.count > 1).forEach((e) => mf.push({ level: "warn", text: `PageView disparado ${e.count}x para o pixel ${e.id}: possível instalação duplicada.` }));
    events.filter((e) => e.ev === "Purchase" && !e.value).forEach((e) => mf.push({ level: "warn", text: `Purchase sem valor (cd[value]) no pixel ${e.id}: a otimização de campanha perde a receita.` }));
    if (events.length && !events.some((e) => e.eventId)) mf.push({ level: "info", text: "Nenhum event_id nos eventos: se houver Conversions API (servidor), a deduplicação depende dele." });
    if (events.length && !meta.cookies._fbp) mf.push({ level: "info", text: "Cookie _fbp ausente apesar dos eventos: o navegador ou o consentimento pode estar bloqueando." });
  }

  // ----- Google
  const gr = raw.google;
  const containers = Object.keys(raw.gtm.containers).map((id) => ({ id, ...raw.gtm.containers[id] }));
  const dataLayers = Object.keys(raw.gtm.dataLayers).map((name) => {
    const d = raw.gtm.dataLayers[name];
    return {
      name,
      length: d.length,
      ecommerce: d.ecommerce,
      consent: d.consent,
      events: Object.keys(d.events).map((n) => ({ name: n, count: d.events[n] })).sort(byCount)
    };
  });
  const tags = Object.keys(gr.ids).map((id) => ({ id, kind: tagKind(id), sources: gr.ids[id] }));
  const ga4 = gr.ga4.slice().sort(byCount);
  const ua = gr.ua.slice().sort(byCount);
  const ads = gr.ads.slice().sort(byCount);
  const serverSide = [...new Set(ga4.map((h) => h.host).filter((h) => h && !GOOGLE_HOST_RE.test(h)))];

  const consentDl = dataLayers.find((d) => d.consent);
  const consent = consentDl
    ? { default: consentDl.consent.default, update: consentDl.consent.update, v2: !!(consentDl.consent.default && ("ad_user_data" in consentDl.consent.default || "ad_personalization" in consentDl.consent.default)) }
    : null;

  const cookies = {
    _ga: hasCookie("_ga"),
    ga4Streams: cookieNames.filter((c) => /^_ga_[a-z0-9]+$/.test(c)).map((c) => "G-" + c.slice(4).toUpperCase()),
    _gid: hasCookie("_gid"),
    _gcl_au: hasCookie("_gcl_au")
  };

  const google = { containers, dataLayers, tags, ga4, ua, ads, serverSide, consent, cookies, hasGtag: gr.hasGtag, findings: [] };
  const gf = google.findings;
  const anyGoogle = containers.length > 0 || tags.length > 0;

  containers.filter((c) => !c.global && c.hosts.length).forEach((c) => gf.push({ level: "warn", text: `Container ${c.id} carregado no HTML, mas não inicializou na página (bloqueado ou com erro).` }));
  containers.filter((c) => !c.noscript).forEach((c) => gf.push({ level: "info", text: `Sem <noscript> do GTM para ${c.id} (recomendado logo após <body>, impacto baixo).` }));
  dataLayers.forEach((d) => {
    if (d.length && !d.events.some((e) => !e.name.startsWith("gtm."))) gf.push({ level: "info", text: `${d.name} só tem eventos nativos do GTM: nenhum evento customizado ou de e-commerce.` });
  });
  tags.filter((t) => t.id.startsWith("UA-")).forEach((t) => gf.push({ level: "warn", text: `${t.id}: Universal Analytics foi descontinuado, migrar para GA4.` }));
  const ga4Ids = tags.filter((t) => t.id.startsWith("G-")).map((t) => t.id);
  if (ga4Ids.length > 1) gf.push({ level: "info", text: `${ga4Ids.length} IDs G-: confirme que cada propriedade é intencional.` });
  ga4Ids.forEach((id) => {
    const hits = ga4.filter((h) => h.tid === id);
    const views = hits.filter((h) => h.en === "page_view").reduce((n, h) => n + h.count, 0);
    if (hits.length && !views && hits.every((h) => h.en)) gf.push({ level: "warn", text: `${id}: hits do GA4 sem page_view na carga da página.` });
    if (views > 1) gf.push({ level: "warn", text: `${id}: ${views} page_view na mesma carga: possível contagem em dobro (gtag.js e GTM juntos?).` });
    if (!hits.length && !raw.bufferFull) gf.push({ level: "info", text: `${id} encontrado no código, mas nenhum hit de coleta foi observado (consentimento pendente ou bloqueio).` });
  });
  if (containers.length && tags.some((t) => t.sources.includes("gtag.js"))) gf.push({ level: "info", text: "gtag.js direto e GTM na mesma página: confirme que o GA4 não é disparado pelos dois." });
  if (serverSide.length) gf.push({ level: "info", text: `Coleta do GA4 por domínio próprio (${serverSide.join(", ")}): indica server-side tagging ou proxy.` });
  if ((anyGoogle || metaDetected) && !consent) gf.push({ level: "info", text: "Google Consent Mode não detectado no dataLayer. Relevante para LGPD se há banner de cookies." });
  if (consent && consent.default && !consent.v2) gf.push({ level: "info", text: "Consent Mode sem ad_user_data/ad_personalization (v2 é exigido para anúncios no EEE)." });
  if (raw.bufferFull && anyGoogle) gf.push({ level: "info", text: "Buffer de requisições cheio (250): hits tardios do Google podem não ter sido capturados." });

  return { entries: raw.entries, bufferFull: raw.bufferFull, meta, google };
}

// Linhas pro relatório em texto (cópia, .md e prompt da IA).
function trackingReportLines(view) {
  if (!view) return [];
  const L = [];
  const m = view.meta;
  const g = view.google;
  L.push("Tracking e marketing:");
  if (m.detected) {
    L.push(`- Meta Pixel: ${m.pixels.map((p) => p.id).join(", ") || "ID não identificado"}${m.libVersion ? ` (fbevents ${m.libVersion})` : ""}`);
    if (m.events.length) L.push(`  Eventos: ${m.events.map((e) => `${e.ev} x${e.count}${e.ev === "Purchase" && !e.value ? " (sem valor)" : ""}`).join(", ")}`);
    else L.push("  Eventos: nenhum observado");
  } else {
    L.push("- Meta Pixel: não detectado");
  }
  if (g.containers.length) {
    L.push(`- Google Tag Manager: ${g.containers.map((c) => `${c.id}${c.global ? "" : " (não inicializou)"}`).join(", ")}`);
    g.dataLayers.forEach((d) => {
      const custom = d.events.filter((e) => !e.name.startsWith("gtm."));
      L.push(`  ${d.name}: ${d.length} entradas, eventos customizados: ${custom.length ? custom.slice(0, 12).map((e) => `${e.name} x${e.count}`).join(", ") : "nenhum"}`);
    });
  } else {
    L.push("- Google Tag Manager: não detectado");
  }
  if (g.tags.length) L.push(`- Tags Google: ${g.tags.map((t) => `${t.id} (${t.kind})`).join(", ")}`);
  else L.push("- Google Analytics/Ads: nenhuma tag detectada");
  if (g.ga4.length) L.push(`  Hits GA4: ${g.ga4.map((h) => `${h.en || "(lote)"} x${h.count}`).join(", ")}`);
  if (g.ads.length) L.push(`  Conversões Google Ads: ${g.ads.map((a) => a.id + (a.label ? "/" + a.label : "") + ` x${a.count}`).join(", ")}`);
  L.push(`- Consent Mode: ${g.consent ? (g.consent.v2 ? "detectado (v2)" : "detectado (sem sinais v2)") : "não detectado"}`);
  const all = [...m.findings, ...g.findings].filter((f) => f.level !== "ok");
  if (all.length) {
    L.push("  Diagnóstico:");
    all.forEach((f) => L.push(`  - ${f.text}`));
  }
  return L;
}

// ---------------------------------------------------------------- interface

function trEl(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function trCard(title, icon) {
  const card = trEl("div", "links-container tr-card");
  card.appendChild(trEl("div", "section-title", (icon ? icon + " " : "") + title));
  return card;
}

function trKv(list, label, value) {
  const li = trEl("li", "kv-row");
  li.appendChild(trEl("span", "kv-label", label));
  const v = trEl("span", "kv-value");
  if (value instanceof Node) v.appendChild(value);
  else v.textContent = value;
  li.appendChild(v);
  list.appendChild(li);
}

function trChips(items, cls) {
  const wrap = trEl("span", "chip-row");
  items.forEach((t) => wrap.appendChild(trEl("span", "tracker-badge" + (cls ? " " + cls : ""), t)));
  return wrap;
}

function trFindings(findings) {
  const card = trCard("Diagnóstico", "🩺");
  if (!findings.length) {
    card.appendChild(trEl("div", "hint", "Nenhum problema evidente nos dados observados."));
    return card;
  }
  const ul = trEl("ul", "findings");
  findings.forEach((f) => ul.appendChild(trEl("li", "finding finding-" + f.level, f.text)));
  card.appendChild(ul);
  return card;
}

function trList() {
  return trEl("ul", "kv-list tr-list");
}

function trEmpty(text) {
  return trEl("div", "empty-state", text);
}

const TRACKING_PENDING_TEXT = "Analisando a página...";
const TRACKING_BLOCKED_TEXT = "Não foi possível analisar esta página (injeção de script bloqueada).";

function drawMetaPixel(root, view) {
  root.innerHTML = "";
  if (view === undefined) return root.appendChild(trEmpty(TRACKING_PENDING_TEXT));
  if (!view) return root.appendChild(trEmpty(TRACKING_BLOCKED_TEXT));
  const m = view.meta;
  if (!m.detected) {
    root.appendChild(trEmpty("Nenhum Meta Pixel detectado nesta página."));
    root.appendChild(trEl("div", "hint", "Se o site usa banner de cookies, o pixel pode só carregar depois do aceite. Aceite e escaneie de novo."));
    return;
  }

  const main = trCard("Meta Pixel", "📘");
  const list = trList();
  if (!m.pixels.length) trKv(list, "Pixel ID", "não identificado");
  m.pixels.forEach((p) => trKv(list, "Pixel " + p.id, trChips(p.sources)));
  if (m.libVersion) trKv(list, "fbevents.js", "v" + m.libVersion);
  trKv(list, "Instalação", m.inlineInit ? "código direto na página" : "sem fbq('init') no HTML (provável GTM/plugin)");
  trKv(list, "Advanced Matching", m.advancedMatching ? "ativo (dados do usuário em hash)" : "não detectado");
  trKv(list, "<noscript>", m.noscript ? "presente" : "ausente");
  trKv(list, "Cookies", `_fbp ${m.cookies._fbp ? "✓" : "✗"}   _fbc ${m.cookies._fbc ? "✓" : "✗"}`);
  main.appendChild(list);
  root.appendChild(main);

  const ev = trCard("Eventos disparados nesta página", "📡");
  if (!m.events.length) {
    ev.appendChild(trEl("div", "hint", "Nenhum evento observado até agora."));
  } else {
    const ul = trList();
    m.events.forEach((e) => {
      const tags = [];
      if (e.value) tags.push("valor" + (e.currency ? " " + e.currency : ""));
      if (e.userData) tags.push("dados do usuário");
      if (e.eventId) tags.push("event_id");
      const v = trEl("span", "chip-row");
      v.appendChild(trEl("span", "", "x" + e.count));
      tags.forEach((t) => v.appendChild(trEl("span", "tracker-badge", t)));
      trKv(ul, e.ev + (m.pixels.length > 1 ? ` (${e.id.slice(-4)})` : ""), v);
    });
    ev.appendChild(ul);
  }
  ev.appendChild(trEl("div", "hint", `${view.entries} requisições na página${view.bufferFull ? " (buffer cheio)" : ""}. Só aparece o que já disparou até o scan.`));
  root.appendChild(ev);
  root.appendChild(trFindings(m.findings));
}

function drawGoogle(root, view) {
  root.innerHTML = "";
  if (view === undefined) return root.appendChild(trEmpty(TRACKING_PENDING_TEXT));
  if (!view) return root.appendChild(trEmpty(TRACKING_BLOCKED_TEXT));
  const g = view.google;
  if (!g.containers.length && !g.tags.length) {
    root.appendChild(trEmpty("Nenhum GTM, GA4 ou Google Ads detectado nesta página."));
    root.appendChild(trEl("div", "hint", "Se o site usa banner de cookies, as tags podem só carregar depois do aceite."));
    root.appendChild(trFindings(g.findings));
    return;
  }

  const gtm = trCard("Google Tag Manager", "🏷️");
  if (!g.containers.length) {
    gtm.appendChild(trEl("div", "hint", "Nenhum container GTM (as tags estão direto na página)."));
  } else {
    const list = trList();
    g.containers.forEach((c) => {
      const chips = [];
      chips.push(c.global ? "ativo" : "não inicializou");
      chips.push(c.hosts.length ? "origem " + c.hosts.join(", ") : "no HTML");
      chips.push(c.noscript ? "noscript ✓" : "noscript ✗");
      trKv(list, c.id, trChips(chips));
    });
    g.dataLayers.forEach((d) => {
      trKv(list, d.name, `${d.length} entradas${d.ecommerce ? ", com ecommerce" : ""}`);
      d.events.slice(0, 12).forEach((e) => trKv(list, "↳ " + e.name, "x" + e.count));
    });
    gtm.appendChild(list);
  }
  root.appendChild(gtm);

  const ga = trCard("Google Analytics e tags Google", "📊");
  if (!g.tags.length) {
    ga.appendChild(trEl("div", "hint", "Nenhuma tag G-, UA-, AW- ou DC- encontrada."));
  } else {
    const list = trList();
    g.tags.forEach((t) => trKv(list, t.id, trChips([t.kind, ...t.sources])));
    ga.appendChild(list);
  }
  if (g.ga4.length) {
    ga.appendChild(trEl("div", "hint", "Hits GA4 observados:"));
    const list = trList();
    g.ga4.forEach((h) => trKv(list, h.en || "(lote)", "x" + h.count + (h.tid && g.tags.filter((t) => t.id.startsWith("G-")).length > 1 ? " " + h.tid : "")));
    ga.appendChild(list);
  }
  if (g.ua.length) {
    const list = trList();
    g.ua.forEach((h) => trKv(list, "UA " + (h.t || "hit"), "x" + h.count));
    ga.appendChild(list);
  }
  const cl = trList();
  trKv(cl, "Cookies", `_ga ${g.cookies._ga ? "✓" : "✗"}   _gid ${g.cookies._gid ? "✓" : "✗"}   _gcl_au ${g.cookies._gcl_au ? "✓" : "✗"}`);
  if (g.cookies.ga4Streams.length) trKv(cl, "Streams GA4 (cookie)", g.cookies.ga4Streams.join(", "));
  ga.appendChild(cl);
  root.appendChild(ga);

  if (g.ads.length) {
    const ads = trCard("Google Ads", "💰");
    const list = trList();
    g.ads.forEach((a) => trKv(list, a.id, (a.label ? "label " + a.label + " " : "") + "x" + a.count));
    ads.appendChild(list);
    root.appendChild(ads);
  }

  const cm = trCard("Consent Mode", "🍪");
  if (!g.consent) {
    cm.appendChild(trEl("div", "hint", "Não detectado no dataLayer."));
  } else {
    const list = trList();
    trKv(list, "Versão", g.consent.v2 ? "v2" : "v1 (sem ad_user_data/ad_personalization)");
    const show = (label, state) => {
      if (!state) return;
      Object.keys(state).forEach((k) => trKv(list, `${label} ${k}`, state[k] === "granted" ? "concedido" : "negado"));
    };
    show("padrão", g.consent.default);
    show("atualizado", g.consent.update);
    cm.appendChild(list);
  }
  root.appendChild(cm);
  root.appendChild(trFindings(g.findings));
}

if (typeof module !== "undefined") {
  module.exports = { analyzeTracking, trackingReportLines };
}
