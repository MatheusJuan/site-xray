# SiteXray

Extensão de navegador (Chrome, Manifest V3) que analisa o site aberto na aba
ativa e mostra, em um popup com abas, informações públicas úteis para
diagnóstico: detecção de WordPress, links sensíveis do WP, sitemap,
rastreadores/pixels de marketing, tecnologia usada no site, segurança
(headers + HTTPS) e SEO on-page (title, headings, imagens, links, social).

Contexto de uso: o autor é freelancer/dev front-end que atende clientes de
sites (muitos em WordPress) e usa a extensão para analisar rapidamente o site
de um cliente ou prospect antes de uma proposta.

## Stack

Vanilla JS, sem build step, sem dependências externas. Só HTML + CSS + JS puro
rodando como popup de extensão MV3.

## Arquivos

```
wp-link-scanner/
├── manifest.json   # MV3, permissions: activeTab, scripting; host_permissions: http/https all_urls
├── popup.html      # estrutura do popup
├── popup.css       # tema visual (dark "hacker", ver seção Design abaixo)
└── popup.js        # toda a lógica
```

Versão atual do manifest: **1.7.0**.

Nome de exibição da extensão (`manifest.json` -> `name`): **SiteXray**. A
pasta do projeto continua `wp-link-scanner/` por motivos históricos, sem
relação com o nome exibido ao usuário.

**Sempre que uma alteração for feita no código, subir o `version` no
`manifest.json` (semver simples: patch para ajustes pequenos, minor para
novas seções/funcionalidades).**

## Funcionalidades atuais

O popup roda `runScan()` automaticamente ao abrir (`DOMContentLoaded`) e tem
um botão "Escanear novamente". A partir da v1.6.0 o conteúdo é organizado em
**abas** (`.tab-btn` / `.tab-panel`, trocadas via JS puro, sem lib): **Visão
Geral**, **Segurança**, **SEO** e **Element Info**. Dentro de SEO tem
sub-abas (`.subtab-btn` / `.subtab-panel`): Resumo, Headers, Imagens, Links,
Social.

Sempre visível, fora das abas: header, status do scan, ferramentas de
domínio, botão "Escanear novamente" e botão "Copiar relatório".

Todo o conteúdo dentro das abas é **independente entre si** — nenhuma seção
depende da detecção de WordPress ter dado certo, exceto os links sensíveis
de WordPress dentro de Visão Geral.

### Sempre visível (fora das abas)

- **Ferramentas de domínio**: link WHOIS (`who.is/whois/{hostname}`), link
  fixo pro sitemap padrão (`{origin}/sitemap.xml`), busca no Google com
  `site:{hostname}`
- **Copiar relatório**: botão "📋 Copiar relatório" monta um texto em
  português com origem, data, tecnologia detectada, status de WordPress,
  links sensíveis achados (severidade + risco), rastreadores/pixels,
  segurança (headers + HTTPS forçado) e um resumo de SEO on-page. Usa
  `navigator.clipboard.writeText`, pronto pra colar em orçamento/proposta

### Aba Visão Geral

1. **Sitemap** — descoberto por 3 fontes, nessa ordem de prioridade:
   1. Linhas `Sitemap:` do `robots.txt`
   2. Tag `<link rel="sitemap">` no `<head>` do HTML da home
   3. Lista de caminhos padrão como fallback (`/sitemap.xml`,
      `/sitemap_index.xml`, `/sitemap-index.xml`, `/wp-sitemap.xml`,
      `/page-sitemap.xml`, `/post-sitemap.xml`)
   - Resultado deduplicado por URL, só mostra os que responderam `ok`
   - Botão "Abrir todos" (abre em abas de fundo, ver seção UX abaixo)

2. **Rastreadores e pixels na página** — usa
   `chrome.scripting.executeScript` com `world: "MAIN"` na aba ativa (lê a
   página já renderizada, incluindo scripts injetados dinamicamente).
   Detecta via `window.*` globals e/ou `<script src>`: Meta Pixel, Google
   Tag Manager, Google Analytics, Google Ads, TikTok Pixel, Pinterest Tag,
   Snapchat Pixel, LinkedIn Insight Tag, Twitter/X Pixel, Hotjar, Microsoft
   Clarity, Jetpack Stats, HubSpot, Matomo/Piwik, Google reCAPTCHA, Criteo,
   Taboola, Outbrain. Badges simples, sem severidade

3. **Tecnologia detectada** — fingerprint próprio (`TECH_SIGNATURES`, tipo
   Wappalyzer caseiro, sem dependência externa), via HTML estático da home
   e headers de resposta:
   - CMS/page builder: Shopify, Wix, Squarespace, Webflow, Drupal, Joomla
   - Framework JS: Next.js, Nuxt.js, Angular, Vue.js (cobertura parcial, só
     HTML estático, sem executar JS)
   - E-commerce: WooCommerce, PrestaShop, Magento
   - CSS framework: Bootstrap
   - CDN/hosting: Cloudflare, Vercel, Netlify, Fastly, Amazon CloudFront
   - Header `Server` cru também vira badge (ex: "Servidor: nginx")
   - WordPress usa a detecção própria (mais confiável, fallback em
     `/wp-json/`) e aparece nessa mesma lista quando identificado

4. **Detecção de WordPress + links sensíveis** (só aparece se detectado) —
   detecção via sinais no HTML da home (`wp-content`, `wp-includes`,
   `wp-json`, meta generator) e, como fallback, confirma direto batendo em
   `/wp-json/`. Se detectado, testa `CANDIDATE_PATHS` e classifica por
   **severidade**: 🔴 crítico / 🟡 atenção / 🟢 info
   - Exemplos: `wp-json/wp/v2/users` (crítico, expõe usuários), `xmlrpc.php`
     (atenção, brute force), `readme.html` (atenção, versão exposta),
     `wp-content/uploads|plugins|themes` (escala pra crítico se detectar
     listagem de diretório ativa via regex `index of /`)
   - Botão "Abrir todos"

### Aba Segurança

Reaproveita a resposta já buscada em `fetchHomepage` (sem fetch extra):
- Presença de `Strict-Transport-Security`, `Content-Security-Policy`,
  `X-Frame-Options`
- Se `http://` redireciona pra `https://` (só testa quando o site já é
  acessado via https)
- Cada item mostra OK/Ausente com nota (borda verde = ok, amarela = ausente)

### Aba SEO

Uma única chamada a `chrome.scripting.executeScript` (`extractSeoData`,
`world: "MAIN"`) lê o DOM já renderizado e alimenta as 5 sub-abas:

- **Resumo**: title (+ contagem de caracteres), description (+ contagem),
  keywords, URL, canonical, robots meta, author, publisher, lang, contagem
  de H1-H6, total de imagens e links
- **Headers**: árvore de H1 a H6 na ordem em que aparecem na página,
  indentado por nível
- **Imagens**: total, quantas sem ALT, quantas sem title; lista separada em
  "Sem ALT ou Title" (problema) e "Completas"
- **Links**: todos os `<a href>`, deduplicados por (href + texto do link),
  com contagem de repetição; clique abre em aba de fundo. Depois da lista
  vir do DOM, uma segunda passada testa o status HTTP só dos links
  **internos** (mesmo origin), com teto de `LINK_STATUS_CAP` (40)
  requisições únicas, pra achar link quebrado/redirecionamento sem virar
  crawler. Badge verde/amarelo por link testado; links externos ou além do
  teto ficam sem badge de status. Entra no relatório copiável quando acha
  algum quebrado
- **Social**: tags Open Graph (`og:*`) e Twitter Card (`twitter:*`)

### Aba Element Info

Inspetor visual de elemento, tipo DevTools simplificado. Diferente de todas
as outras abas: o resultado **não aparece dentro do popup**, porque o popup
fecha ao clicar na página. Em vez disso, o botão "Ativar inspector de
elementos" injeta `startElementInspector` (função autocontida em
`popup.js`, via `chrome.scripting.executeScript`, world isolado por
padrão) direto na página:

- Hover destaca o elemento sob o cursor com borda verde (`document.elementFromPoint`
  em cima do `mousemove`, capturado em `document` com `capture: true`)
- Clique intercepta a navegação (`preventDefault` + `stopPropagation` na
  fase de captura) e fixa a seleção
- Painel fica num Shadow DOM (`attachShadow`) fixo no rodapé da página, com
  tema SiteXray hardcoded em string (não tem acesso ao `popup.css`), pra não
  vazar nem sofrer interferência do CSS do site do cliente
- Mostra DOM (outerHTML truncado em 1500 chars), Layout (`width`/`height`
  via `getBoundingClientRect`), Position (`display`/`float`/`position` via
  `getComputedStyle`), Text (`font-family`/`font-size`/`line-height`),
  breadcrumb de Ancestors e lista de Children — cada um clicável pra
  re-inspecionar aquele nó
  - Botão "Copiar" por bloco, com fallback pra `document.execCommand("copy")`
    quando `navigator.clipboard` não existe (sites `http://` não são secure
    context)
- Sai com `Esc` ou botão "Fechar" no painel; um flag em
  `window.__sitexrayInspectorActive` evita injeção duplicada
- **Editar ao vivo (HTML/CSS) ficou de fora de propósito**: risco de quebrar
  o site do cliente é maior que o resto da extensão, que é só leitura. Só
  entra se fizer falta na prática

## Decisões de arquitetura importantes

- **Sitemap e trackers foram deliberadamente desacoplados da detecção de
  WordPress.** Motivo: a detecção de WP pode falhar por falso negativo (CDN
  reescrevendo HTML, cache agressivo, etc.), e isso não deve esconder dados
  que são úteis pra qualquer site, WP ou não.
- **Links abrem em aba de fundo (`chrome.tabs.create({ url, active: false })`),
  nunca com `target="_blank"` normal.** Motivo: popup de extensão fecha
  automaticamente ao perder foco; abrir a aba sem trazer foco pra ela mantém
  o popup aberto, permitindo clicar em vários links em sequência sem reabrir
  o popup toda hora. Isso vale pra todo link clicável no popup (sitemap,
  links de WP, WHOIS, Google, sitemap padrão).
- **Todo fetch usa timeout de 6s** (`AbortController`) pra não travar em
  sites lentos.
- Nenhum dado é persistido (`chrome.storage` não é usado ainda) — cada scan é
  from scratch.

## Design (tema visual)

Tema dark "hacker terminal", definido via CSS custom properties no topo do
`popup.css`:

- Popup com **420px** de largura (subiu de 340px na v1.6.0 pra caber abas e
  listas de SEO como imagens/links sem espremer)
- Fundo quase preto (`--bg: #0a0e12`) com leve glow radial verde/ciano nos
  cantos
- Fonte monoespaçada (`--mono`, JetBrains Mono com fallbacks)
- Cor de destaque primária: verde neon (`--accent: #39ff9e`) — usado em
  títulos, botões, status positivo, badges de sucesso
- Cor secundária: ciano (`--cyan: #2fe0ff`) — usado em links clicáveis
- Vermelho (`--danger`) e amarelo (`--warn`) mantidos para severidade
  crítica/atenção
- Botões são outline (borda colorida, fundo transparente) e invertem cor no
  hover
- Título do popup tem um `>` na frente simulando prompt de terminal
- Scrollbar customizada fina

## Preferências do usuário aplicadas neste projeto

- Nunca usar travessão em textos/respostas
- Idioma da interface: português
- Prefere respostas objetivas focadas em melhoria/otimização

## Ideias de melhorias já discutidas e ainda não implementadas

Ordenadas por impacto x esforço, conversadas mas não construídas ainda:

- Detecção de plugins e tema ativo do WordPress (via caminhos de CSS/JS
  carregados na home, ex: `wp-content/plugins/nome-do-plugin/`) — baixa
  prioridade porque a base de clientes é mista (WP e outras stacks), esse
  item só ajuda a fatia WP
- Histórico por domínio via `chrome.storage`, pra comparar scans ao longo do tempo
- Exportar resultado em JSON/CSV
- Badge no ícone da toolbar mostrando contagem de itens críticos/atenção sem
  precisar abrir o popup
- Rodar scan automático em background (`background.js` + `setBadgeText`) ao
  invés de só sob demanda ao abrir o popup

## Como testar localmente

1. `chrome://extensions`
2. Ativar "Modo do desenvolvedor"
3. "Carregar sem compactação" apontando pra pasta `wp-link-scanner/`
4. Ao mudar `manifest.json` (ex: novas permissions), remover e carregar de
   novo em vez de só recarregar, pra evitar problema de permissão cacheada
