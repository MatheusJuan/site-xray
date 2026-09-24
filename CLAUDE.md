# SiteXray

Extensão de navegador (Chrome, Manifest V3) que analisa o site aberto na aba
ativa e mostra, em um popup com abas, informações públicas úteis para
diagnóstico: detecção de WordPress, links sensíveis do WP, sitemap,
subdomínios, rastreadores/pixels de marketing, tecnologia usada no site,
segurança (headers, HTTPS, arquivos expostos, cookies, redirects), SEO
on-page (title, headings, imagens, links, social, tags do head, dados
estruturados, favicon) e um inspetor visual de elementos.

Contexto de uso: o autor é freelancer/dev front-end que atende clientes de
sites (base mista: muitos em WordPress, mas também Shopify, SPAs e outras
stacks) e usa a extensão para analisar rapidamente o site de um cliente ou
prospect antes de uma proposta. O botão "Copiar relatório" existe justamente
pra levar o resultado pra orçamento/proposta.

Este arquivo é a documentação técnica completa do projeto, feita pra qualquer
sessão futura (humana ou de IA) entender tudo sem reler a conversa que gerou o
código. O `README.md` da raiz é o texto voltado a quem só quer instalar e usar.

## Stack

Vanilla JS, sem build step, sem dependências externas, sem backend. Só HTML +
CSS + JS puro rodando como popup de extensão MV3. Nenhum framework, nenhum
bundler, nenhum `package.json`. Tudo o que a extensão consulta na rede é
público e gratuito (o próprio site analisado, `crt.sh`, `raw.githubusercontent.com`).

## Repositório e fluxo de trabalho

- Repo: <https://github.com/MatheusJuan/site-xray>, branch `master` (única).
- Remote `origin` usa **HTTPS** (`https://github.com/MatheusJuan/site-xray.git`),
  autenticado via `gh auth login` + `gh auth setup-git`. Não usar SSH: a chave
  `~/.ssh/id_ed25519` da máquina está cadastrada como *deploy key* de outro
  repo (`saas-pet-lp`), então o GitHub não deixa reaproveitá-la como chave de
  conta ("Key is already in use") e o push por SSH dá permission denied.
- Máquina do autor: Windows 11, Git Bash disponível, `node` disponível (usado
  só pra validar sintaxe, ver "Como validar").
- Cada mudança segue o mesmo ciclo: implementar, validar, **avisar o usuário e
  perguntar se quer commit e push**, e só então commitar. Nunca commitar ou
  dar push sem o usuário pedir.
- Mensagens de commit em inglês, formato `tipo: resumo` (`feat:`, `fix:`,
  `docs:`), corpo explicando o porquê, terminando com a linha
  `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.
- O git converte LF em CRLF nos arquivos (warning inofensivo em todo commit).
- A pasta do projeto no disco é `extensão-chrome-analise/` e a extensão em si
  fica em `wp-link-scanner/` (nome histórico, ver abaixo).

## Arquivos

```
extensão-chrome-analise/
├── CLAUDE.md               # este arquivo (documentação técnica completa)
├── README.md               # apresentação, instalação e uso, voltado ao usuário final
└── wp-link-scanner/        # a extensão (é esta pasta que se carrega no Chrome)
    ├── manifest.json       # MV3, permissions: activeTab, scripting, cookies, sidePanel, storage;
    │                       # host_permissions: http://*/* e https://*/*
    ├── popup.html          # estrutura do popup (~180 linhas)
    ├── popup.css           # tema visual dark "hacker" (~670 linhas)
    ├── popup.js            # toda a lógica (~2000 linhas, arquivo único)
    └── icons/
        ├── icon.png        # ícone da extensão, 519x519 RGBA
        └── logo.png        # logomarca "SITExRAY" do header, 1359x205 RGBA
```

Versão atual do manifest: **1.15.1**.

Nome de exibição (`manifest.json` `name`): **SiteXray**. A pasta continua
`wp-link-scanner/` por motivos históricos (era o nome original, "WP Link
Scanner", quando a extensão só detectava WordPress), sem relação com o nome
exibido ao usuário. Renomear a pasta quebraria `REPO_MANIFEST_URL` e o
caminho que o usuário já usa no Chrome, então foi deixada como está.

`manifest.json` usa o mesmo `icons/icon.png` pras 4 chaves de tamanho
(16/32/48/128) e pro `action.default_icon`. Só um arquivo fonte, sem gerar
tamanhos separados, porque não havia ferramenta de resize disponível. Se algum
dia o ícone ficar borrado na barra de 16px, gerar versões dedicadas resolve.

### Regra de versionamento (importante)

**Sempre que uma alteração for feita no código, subir o `version` no
`manifest.json`** (semver simples: patch para ajustes e correções pequenas,
minor para novas seções/funcionalidades).

Isso não é só organização: o botão Dev compara a versão instalada com a do
`manifest.json` que está na branch `master` do GitHub. Subir a versão e dar
push é o que faz o aviso "Atualização disponível" aparecer pra quem já tem a
extensão instalada. Mudança sem bump de versão fica invisível pra esse aviso.

### Histórico de versões

| Versão | Commit | O que entrou |
| --- | --- | --- |
| 1.3.0 | `ae2e6ab` | Estado inicial (ponto de restauração): detecção de WP, links sensíveis, sitemap, rastreadores, WHOIS |
| 1.4.0 | `5a41ab3` | Botão "Copiar relatório" |
| 1.4.1 | `0471ea9` | Renomeada pra SiteXray |
| 1.5.0 | `2cb91d1` | Fingerprint de tecnologia + headers de segurança + HTTPS forçado |
| 1.5.1 | `d2988a7` | Fingerprint ampliado (frameworks JS, e-commerce, CDN, header Server) |
| 1.6.0 | `134318a` | Popup em abas (Visão Geral, Segurança, SEO) + análise de SEO on-page |
| 1.6.1 | `70ebaba` | Status HTTP dos links internos na aba SEO |
| 1.7.0 | `21a7c7d` | Aba Element Info (inspetor visual) |
| 1.7.1 | `18b9181` | Bloco Colors no inspetor |
| 1.7.2 | `2191f09` | WHOIS via registro.br + botão DNS Checker |
| 1.8.0 | `a3c9092` | Ícone, logo no header, botão Dev com checagem de atualização |
| 1.9.0 | `e1d8c05` | Subdomínios via crt.sh |
| 1.9.1 | `d26e997` | Diferencia crt.sh fora do ar de "nenhum subdomínio" |
| 1.9.2 | `26a695c` | Miniatura e link nas imagens da aba SEO |
| 1.10.0 | `4cab53c` | Tags `<head>`, dados estruturados (JSON-LD), favicon com download |
| 1.11.0 | `6078ab8` | Checagens passivas de segurança: arquivos sensíveis, cookies, redirects, mais headers |
| 1.12.0 | pendente | Side panel (troca de aba refaz o scan) e cache por origem em `chrome.storage.session` (10 min), Web Vitals (LCP/CLS/TTFB), impacto de recursos de terceiros, z-index/opacity no inspetor |
| 1.13.0 | pendente | Fix HSTS em redirects (mescla headers da cadeia), nota de segurança A–F, exportar relatório `.md` |
| 1.14.0 | pendente | PageSpeed Insights sob demanda, badge no ícone, histórico por domínio, plugins/tema WP, mixed content, robots.txt, +tech signatures, export `.html` |
| 1.14.1 | pendente | HSTS via probe same-origin na página (fetch da extensão escondia o header); histórico não duplica em rescan em menos de 2 min |
| 1.15.0 | pendente | MX/SPF/DMARC via DoH, análise de CSP, integrações (pagamentos/chat/CRM), e-mails + links LGPD, bots de IA no robots + llms.txt, headers COOP/CORP/COEP (sem descontar da nota) |
| 1.15.1 | pendente | Visual: seções em cards com ícone, abas em pílula fixas, ferramentas de domínio em grade, status com indicador, hover com brilho |

(`980ac78` adicionou o `README.md` sem mudar a versão.)

## Estrutura do popup

O popup roda `runScan()` automaticamente ao abrir (`DOMContentLoaded`) e tem
um botão "Escanear novamente". O conteúdo é organizado em **abas**
(`.tab-btn` / `.tab-panel`, trocadas via JS puro, sem lib, dirigidas por
`data-tab` que casa com `id="tab-<nome>"`): **Visão Geral**, **Segurança**,
**SEO** e **Element Info**. Dentro de SEO existem 7 sub-abas
(`.subtab-btn` / `.subtab-panel`, dirigidas por `data-subtab` que casa com o
`id` do painel): Resumo, Headers, Imagens, Links, Social, Tags `<head>` e
Dados Estruturados.

Sempre visível, fora das abas: header (logo + botão Dev), status do scan,
ferramentas de domínio, barra de abas, botão "Escanear novamente" e botões
de relatório (Copiar, `.md`, `.html`).

Todo o conteúdo dentro das abas é **independente entre si**. Nenhuma seção
depende da detecção de WordPress ter dado certo, exceto os links sensíveis
de WordPress dentro de Visão Geral. Cada scan dispara suas consultas em
paralelo, sem esperar uma pela outra, e cada bloco renderiza quando a sua
resposta chega.

### Header e botão Dev

O header mostra a logomarca (`icons/logo.png`) no lugar do texto "SiteXray"
que existia antes, com um botão "Dev" alinhado à direita na mesma linha.
Clicar no botão abre/fecha um painel (`#dev-panel`) com:

- Versão instalada (`chrome.runtime.getManifest().version`).
- Checagem de atualização: busca o `manifest.json` direto de
  `raw.githubusercontent.com/MatheusJuan/site-xray/master/wp-link-scanner/manifest.json`
  (com cache-buster `?_=timestamp`, sem usar a API do GitHub pra não esbarrar
  em rate limit) e compara semver com `compareVersions()`. Se a versão remota
  for maior, mostra "🔴 Atualização disponível" e pinta o botão Dev de
  amarelo (`.update-available`); senão, "✅ Você está na versão mais
  recente". Falha de rede mostra "Não foi possível checar atualização".
- Link "📦 Ver repositório no GitHub" (`REPO_URL`, abre em aba de fundo).
- Roda uma vez, direto no `DOMContentLoaded`, independente do `runScan()`.

### Sempre visível (fora das abas)

- **Ferramentas de domínio**: link WHOIS via registro.br
  (`registro.br/tecnologia/ferramentas/whois?search={hostname}`, escolhido
  porque os clientes são majoritariamente `.com.br`), DNS Checker
  (`dnschecker.org/all-dns-records-of-domain.php?query={hostname}/&rtype=ALL&dns=google`,
  o `/` depois do hostname é codificado como `%2F`, exatamente como o site
  gera; lista todos os registros DNS), link fixo pro sitemap padrão
  (`{origin}/sitemap.xml`) e busca no Google com `site:{hostname}`.
- **Copiar relatório**: botão "📋 Copiar relatório" monta (`buildReport()`)
  um texto em português com origem, data, tecnologia detectada, status de
  WordPress, links sensíveis (severidade + risco), rastreadores/pixels,
  segurança (headers + HTTPS + arquivos sensíveis + cookies + candidatos a
  redirect), resumo de SEO on-page (title, description, canonical, favicon,
  JSON-LD, H1, imagens sem ALT, links, links internos quebrados) e sitemaps
  e subdomínios encontrados. Usa `navigator.clipboard.writeText`, pronto pra
  colar em orçamento/proposta. Aparece junto com "Escanear novamente" quando
  o scan termina.

### Aba Visão Geral

1. **Sitemap**: descoberto por 3 fontes, nessa ordem de prioridade:
   1. Linhas `Sitemap:` do `robots.txt`.
   2. Tag `<link rel="sitemap">` no `<head>` do HTML da home.
   3. Lista de caminhos padrão como fallback (`SITEMAP_FALLBACK_PATHS`:
      `/sitemap.xml`, `/sitemap_index.xml`, `/sitemap-index.xml`,
      `/wp-sitemap.xml`, `/page-sitemap.xml`, `/post-sitemap.xml`).

   Resultado deduplicado por URL (`dedupeByUrl`), só mostra os que responderam
   `ok`. Botão "Abrir todos" (abre em abas de fundo).

2. **Subdomínios** (sempre roda, independente de ser WordPress): busca em
   `crt.sh` (logs públicos de Certificate Transparency, sem chave, sem
   custo), consulta `?q=%.{hostname}&output=json` e extrai `name_value` de
   cada certificado (pode ter múltiplos SANs por linha, separados por `\n`).
   Filtra só nomes que são o próprio hostname ou terminam em `.{hostname}`
   (checar só `endsWith(hostname)` daria falso positivo com `notexample.com`),
   deduplica e ordena.
   - Lista limitada a `SUBDOMAIN_DISPLAY_CAP` (60) na tela e no "Abrir
     todos", pra não abrir centenas de abas em domínio grande. O relatório
     copiável lista todos os encontrados, sem cap.
   - crt.sh é conhecido por cair com frequência (infra limitada, 502 e
     timeouts são comuns; já foi confirmado em teste direto). `discoverSubdomains`
     distingue os casos: retorna `null` quando a consulta falhou (UI mostra
     "serviço instável ou fora do ar, tenta de novo em alguns minutos") e `[]`
     só quando funcionou mas não achou nada ("nenhum subdomínio encontrado").
     Evita confundir "serviço caiu" com "domínio sem subdomínio".
   - Entradas com wildcard (`*.dominio.com`) aparecem como texto, e o link
     abre o host sem o `*.` (`subdomainUrl`).

3. **Rastreadores e pixels na página**: usa `chrome.scripting.executeScript`
   com `world: "MAIN"` na aba ativa (`scanPageForTrackers`), lendo a página
   já renderizada, incluindo scripts injetados dinamicamente. Detecta via
   `window.*` globals e/ou `<script src>`: Meta Pixel, Google Tag Manager,
   Google Analytics, Google Ads, TikTok Pixel, Pinterest Tag, Snapchat Pixel,
   LinkedIn Insight Tag, Twitter/X Pixel, Hotjar, Microsoft Clarity, Jetpack
   Stats, HubSpot, Matomo/Piwik, Google reCAPTCHA, Criteo, Taboola,
   Outbrain. Badges simples, sem severidade.

4. **Tecnologia detectada**: fingerprint próprio (`TECH_SIGNATURES`, tipo
   Wappalyzer caseiro, sem dependência externa) sobre o HTML estático da home
   e os headers de resposta, ambos vindos do mesmo `fetchHomepage`:
   - CMS/page builder: Shopify, Wix, Squarespace, Webflow, Drupal, Joomla.
   - Framework JS: Next.js, Nuxt.js, Angular, Vue.js (cobertura parcial: só
     HTML estático, sem executar JS; React puro e Svelte não têm marcador
     confiável e ficaram de fora).
   - E-commerce: WooCommerce, PrestaShop, Magento.
   - CSS framework: Bootstrap (Tailwind ficou de fora, classes utilitárias
     dão falso positivo e o build costuma removê-las).
   - CDN/hosting: Cloudflare, Vercel, Netlify, Fastly, Amazon CloudFront.
   - O header `Server` cru também vira badge (ex: "Servidor: nginx").
   - WordPress usa a detecção própria (mais confiável, ver item 5) e aparece
     nessa mesma lista quando identificado.

5. **Detecção de WordPress + links sensíveis** (só aparece se detectado):
   detecção (`detectWordPress`) via sinais no HTML da home (`wp-content`,
   `wp-includes`, `wp-json`, meta generator) e, como fallback, confirma
   batendo em `/wp-json/` e checando se o JSON tem `name`/`namespaces`. Se
   detectado, testa `CANDIDATE_PATHS` (`checkPath`) e classifica cada um por
   **severidade**: 🔴 crítico / 🟡 atenção / 🟢 info.
   - Exemplos: `wp-json/wp/v2/users` (crítico, expõe usuários; lê o JSON e
     mostra quantos e quais), `xmlrpc.php` (atenção, brute force),
     `readme.html` (atenção, tenta extrair a versão exata do WP),
     `wp-content/uploads|plugins|themes` (info, escala pra crítico se
     detectar listagem de diretório ativa via regex `index of /`).
   - Lista ordenada por severidade, cada item mostra status HTTP + nota de
     risco. Botão "Abrir todos".

### Aba Segurança

Tudo **passivo**: só lê o que o site já entrega. Testes ativos (SQL
injection, IDOR, rate limit bypass, mass assignment, business logic etc.)
ficam de fora de propósito: só cabem em site próprio ou com autorização do
cliente, e pertencem a ferramenta de pentest (Burp, scripts à parte), não a
esta extensão. Isso foi discutido explicitamente a partir de um relatório de
pentest que o autor mostrou, e concluiu-se que quase nada daquela lista é
observável passivamente.

- **Headers** (reaproveita a resposta de `fetchHomepage`, sem fetch extra):
  `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
  (`SECURITY_HEADERS`).
- **HTTPS forçado** (`checkHttpsForced`): se `http://` redireciona pra
  `https://`. Só testa quando o site já é acessado via https.
- Cada item mostra OK/Ausente com nota (borda verde = ok, amarela = ausente).
- **Arquivos sensíveis expostos** (`SENSITIVE_PATHS`, `checkSensitiveFiles`):
  `.env`, `.git/config`, `.git/HEAD`, `.htpasswd`, `wp-config.php.bak`,
  `backup.sql`, `db.sql`, `backup.zip`, `phpinfo.php`, `server-status`. Só
  conta como achado se o **conteúdo** bate com o esperado (função `valid` de
  cada entrada), porque SPA responde 200 com `index.html` pra qualquer rota e
  só olhar o status daria falso positivo em quase todo site moderno. Lê só o
  primeiro chunk do corpo (`readHead`, até 4KB) e cancela o resto, pra não
  baixar um zip inteiro. Limitação conhecida: se o servidor mandar um
  primeiro chunk minúsculo, a validação pode dar falso negativo.
- **Cookies** (`getCookieFlags`): usa `chrome.cookies.getAll` (permissão
  `cookies` no manifest). Mostra nome + `Secure`/`HttpOnly`/`SameSite`,
  **nunca o valor** (é dado sensível). Borda amarela quando falta `Secure`
  ou `SameSite` não é `lax`/`strict`. `HttpOnly` ausente aparece no badge mas
  não muda a borda, porque cookie de analytics como `_ga`/`_fbp` nunca tem.
- **Parâmetros de redirect** (`findRedirectCandidates`): varre os links
  **internos** que a aba SEO já coletou, procurando `redirect`,
  `redirect_uri`, `redirect_url`, `return`, `returnurl`, `return_to`, `next`,
  `url`, `continue`, `dest`, `destination`, `goto` na query. Só marca
  **candidato** a Open Redirect, não confirma (confirmar exige testar o
  endpoint com um destino externo).

### Aba SEO

Uma única chamada a `chrome.scripting.executeScript` (`extractSeoData`,
`world: "MAIN"`) lê o DOM já renderizado e alimenta as 7 sub-abas:

- **Resumo**: favicon (detectado via `<link rel="icon">`, `shortcut icon` ou
  `apple-touch-icon`, com fallback `/favicon.ico`) com preview e botão
  "Baixar favicon" (busca como blob e dispara `<a download>`; funciona
  cross-origin porque roda no popup, que tem `host_permissions`), title (+
  contagem de caracteres), description (+ contagem), keywords, URL,
  canonical, robots meta, author, publisher, lang, contagem de H1-H6, total
  de imagens e links.
- **Headers**: árvore de H1 a H6 na ordem em que aparecem na página,
  indentada por nível. (Nome pode confundir com headers HTTP: aqui são os
  títulos `<h1>`-`<h6>`.)
- **Imagens**: total, quantas sem ALT, quantas sem title; lista separada em
  "Sem ALT ou Title" (problema) e "Completas". Cada item mostra miniatura
  (40x40, `object-fit: cover`, esconde sozinha via evento `error` se a
  imagem não carregar) e o nome do arquivo como link (abre a imagem em aba
  de fundo).
- **Links**: todos os `<a href>`, deduplicados por (href + texto do link),
  com contagem de repetição; clique abre em aba de fundo. Depois da lista
  vir do DOM, uma segunda passada (`checkLinkStatuses`) testa o status HTTP
  só dos links **internos** (mesmo origin), com teto `LINK_STATUS_CAP` (40)
  requisições únicas, pra achar link quebrado/redirecionamento sem virar
  crawler. Badge verde/amarelo por link testado; links externos ou além do
  teto ficam sem badge de status. Entra no relatório quando acha algum
  quebrado.
- **Social**: tags Open Graph (`og:*`) e Twitter Card (`twitter:*`).
- **Tags `<head>`**: tabela com todo elemento filho de `<head>` na ordem em
  que aparece (meta, link, script, title, style), com prioridade
  recomendada (charset/viewport = 100, title = 95, script = 70, stylesheet =
  40, preload = 30, resto = 50) e aviso quando a ordem real diverge do
  recomendado (charset que não é a 1ª tag, viewport ou title que aparecem
  depois de CSS/script). A pontuação é uma heurística própria, inspirada em
  uma ferramenta de SEO que o autor mostrou em screenshot; o algoritmo real
  dela não é conhecido, então não há paridade 1:1 e isso é intencional.
- **Dados Estruturados**: percorre todo `<script type="application/ld+json">`
  da página, mostra `@type` + `name`/`headline` de cada nó recursivamente
  (cobre estruturas aninhadas tipo `FAQPage` com `mainEntity` de
  `Question`/`Answer`), com botão "Copiar JSON" por bloco. JSON inválido em
  um bloco é ignorado sem quebrar os outros.

### Aba Element Info

Inspetor visual de elemento, tipo DevTools simplificado. Diferente de todas
as outras abas: o resultado **não aparece dentro do popup**, porque o popup
fecha ao clicar na página. O botão "Ativar inspector de elementos" injeta
`startElementInspector` (função autocontida em `popup.js`, via
`chrome.scripting.executeScript`, world isolado por padrão) direto na página:

- Hover destaca o elemento sob o cursor com borda verde
  (`document.elementFromPoint` em cima do `mousemove`, capturado em
  `document` com `capture: true`).
- Clique intercepta a navegação (`preventDefault` + `stopPropagation` na
  fase de captura) e fixa a seleção.
- Painel num Shadow DOM (`attachShadow`) fixo no rodapé da página (38vh),
  com tema SiteXray hardcoded em string (o injetado não tem acesso ao
  `popup.css`), pra não vazar nem sofrer interferência do CSS do site.
- Mostra DOM (`outerHTML` truncado em 1500 chars), Layout (`width`/`height`
  via `getBoundingClientRect`), Position (`display`/`float`/`position` via
  `getComputedStyle`), Text (`font-family`/`font-size`/`line-height`),
  Colors (`color`, `background-color`, `border-color` computados, com swatch
  visual e conversão pra hex quando o valor vem em `rgb()`/`rgba()`),
  breadcrumb de Ancestors e lista de Children, cada um clicável pra
  re-inspecionar aquele nó.
  - Colors tem botão "Copiar" por linha (copia o hex quando dá pra
    converter, senão o `rgb()` cru); as outras seções têm um "Copiar" por
    bloco inteiro.
  - O copiar tem fallback pra `document.execCommand("copy")` quando
    `navigator.clipboard` não existe (sites `http://` não são secure
    context).
- Sai com `Esc` ou botão "Fechar" no painel; o flag
  `window.__sitexrayInspectorActive` evita injeção duplicada.
- **Editar ao vivo (HTML/CSS) ficou de fora de propósito**: o risco de
  quebrar o site do cliente é maior que o do resto da extensão, que é só
  leitura. Só entra se fizer falta na prática.

## Decisões de arquitetura importantes

- **Sitemap, subdomínios, trackers, tecnologia, segurança e SEO foram
  deliberadamente desacoplados da detecção de WordPress.** Motivo: a
  detecção de WP pode falhar por falso negativo (CDN reescrevendo HTML,
  cache agressivo etc.), e isso não deve esconder dados úteis pra qualquer
  site. Além disso a base de clientes é mista.
- **Links abrem em aba de fundo** (`openInBackground` =
  `chrome.tabs.create({ url, active: false })`), nunca com `target="_blank"`
  normal. Motivo: popup de extensão fecha ao perder foco; abrir a aba sem
  trazer foco pra ela mantém o popup aberto, permitindo clicar em vários
  links em sequência. Vale pra todo link clicável no popup.
- **Todo fetch usa timeout de 6s** (`fetchWithTimeout`, `AbortController`,
  `FETCH_TIMEOUT_MS`) pra não travar em sites lentos. Falha de rede nunca
  quebra a UI: cada consulta faz `try/catch` e degrada pra "não encontrado"
  (exceto crt.sh, que distingue falha de vazio de propósito).
- **Fetches usam o contexto do popup com `host_permissions`**, que permite
  requisições cross-origin sem CORS. Por isso dá pra buscar a home do
  cliente, `crt.sh`, `raw.githubusercontent.com` e binários (favicon) direto
  do `popup.js`, sem service worker nem backend.
- **Nenhum dado é persistido**: `chrome.storage` não é usado. Cada scan é
  do zero, e reabrir o popup refaz tudo (dezenas de requests).
- **Sem backend, de propósito.** Foi discutido (VPS vs Vercel) e descartado:
  a extensão fica 100% client-side, gratuita e sem chaves.

### Alternativas avaliadas e descartadas (pra não rediscutir)

- **Wappalyzer de verdade**: base de fingerprints fechada/paga desde que
  virou produto comercial, sem API grátis pra embutir. Optou-se por lista
  própria (`TECH_SIGNATURES`), que cobre o essencial e fica sob controle.
- **Censys pra listar subdomínios**: exige API key paga (a partir de
  US$100/mês pro nível útil) e chave em código de extensão é visível pra
  qualquer um. Trocado por **crt.sh**, grátis e sem chave, ao custo de ser
  instável e menos rico (sem CVE/banner/screenshot).
- **Nível Screaming Frog (crawl do site inteiro)**: é outro produto, não dá
  numa extensão de popup (MV3 mata o service worker ocioso, popup fecha ao
  perder foco). Exigiria crawler Node com fila, banco e dashboard, num VPS
  (não Vercel, por causa do timeout de function serverless). Ficou só como
  ideia; a versão "mini" já existente é o teste de status dos links
  internos da página atual (`checkLinkStatuses`).
- **Testes ativos de segurança** (ver aba Segurança).
- **Edição ao vivo no inspetor** (ver aba Element Info).

## Gotchas e convenções de código

- **Funções injetadas precisam ser 100% autocontidas.**
  `scanPageForTrackers`, `extractSeoData` e `startElementInspector` são
  serializadas e executadas dentro da página por `executeScript({ func })`.
  Não podem referenciar constantes, helpers ou variáveis do `popup.js`
  (nada de closure). Qualquer helper que elas precisem tem que ser declarado
  dentro delas (ex: `copyText`, `toHex`, `describeEl` dentro do inspetor).
- **`world: "MAIN"` vs isolado.** Trackers e SEO usam `MAIN` porque precisam
  ver globais definidos pelo JS da página (`window.fbq`, `window.ga`...). O
  inspetor usa o mundo isolado padrão porque só precisa de DOM/CSSOM.
- **Nunca interpolar dado da página em `innerHTML`.** Todo texto que vem do
  site analisado (alt, title, href, nomes de cookie, headings, JSON-LD) entra
  via `textContent`/`createElement`. `innerHTML = ""` só é usado pra limpar.
  A única exceção é o esqueleto estático do painel do inspetor.
- **CSS por id em grupos de seletores.** Listas novas (`#foo-list`)
  precisam ser adicionadas manualmente aos grupos de seletores compartilhados
  em `popup.css` (reset da lista, `li` base, `severity-critical/warning/info`,
  `a` e `a:hover`), senão ficam sem estilo. Classes reutilizáveis já
  existentes: `.link-row`, `.risk-note`, `.badge` (`.badge-ok`/`.badge-warn`),
  `.badge-group`, `.kv-row`, `.open-all-btn` (botão pequeno de ação),
  `.tracker-badge`, `.empty-state`, `.hint`, `.section-title`.
- **Severidade visual**: `li.severity-critical` (vermelho), `severity-warning`
  (amarelo), `severity-info` (verde) definem a borda esquerda do item.
- **Adicionar uma seção nova** normalmente exige: markup em `popup.html`
  (dentro do `tab-panel` certo), `getElementById` + variável `lastX` no topo
  do `popup.js`, função `renderX`, chamada em `runScan()` (e reset do
  container no começo dele), entrada em `buildReport()`, e atualização deste
  arquivo, do `README.md` quando for visível ao usuário e do `version`.
- **Falso positivo de SPA**: qualquer checagem por caminho precisa validar o
  conteúdo, não só o status (ver arquivos sensíveis).
- **Sem `innerHTML` significa sem template strings de HTML.** Componentes
  são montados com `document.createElement` em sequência (verboso, mas
  seguro e consistente com o resto do arquivo).

### Mapa do `popup.js` (por ordem de aparição)

- **Constantes**: `CANDIDATE_PATHS` (caminhos WP), `SITEMAP_FALLBACK_PATHS`,
  `SEVERITY_ORDER`/`SEVERITY_LABEL`, `FETCH_TIMEOUT_MS`, `LINK_STATUS_CAP`,
  `SUBDOMAIN_DISPLAY_CAP`, `REPO_URL`, `REPO_MANIFEST_URL`, `TECH_SIGNATURES`,
  `SECURITY_HEADERS`, `SENSITIVE_PATHS`, `REDIRECT_PARAMS`.
- **Referências de DOM** (`getElementById`) e estado (`lastSitemapResults`,
  `lastSubdomains`, `lastFoundResults`, `lastTrackers`, `lastTechStack`,
  `lastSecurityChecks`, `lastSensitiveFiles`, `lastCookies`,
  `lastRedirectCandidates`, `lastIsWordPress`, `lastOrigin`, `lastSeoData`),
  usadas por `buildReport()` e pelos botões "Abrir todos".
- **Rede/utilitários**: `openInBackground`, `fetchWithTimeout`,
   `getActiveTabOrigin`, `fetchHomepage` (devolve `{ html, headers }`),
   `probePageSecurityHeaders` (executeScript same-origin pra HSTS que o
   fetch da extensão não expõe),
  `dedupeByUrl`, `compareVersions`, `checkForUpdate`.
- **Detecção/coleta**: `detectTechStack`, `checkHttpsForced`,
  `buildSecurityChecks`, `readHead`, `checkSensitiveFiles`,
  `getCookieFlags`, `findRedirectCandidates`, `detectWordPress`, `checkPath`,
  `getSitemapsFromRobots`, `getSitemapFromHtml`, `checkAbsoluteUrl`,
  `discoverSitemaps`, `discoverSubdomains`, `checkLinkStatuses`,
  `detectTrackers`, `scanSeo`.
- **Injetadas na página**: `scanPageForTrackers`, `extractSeoData`,
  `startElementInspector` (+ `startInspector`, que faz a injeção).
- **Render**: `renderTrackers`, `renderTech`, `renderSecurity`,
  `renderSensitiveFiles`, `renderCookies`, `renderRedirectCandidates`,
  `renderSitemapList`, `renderSubdomains`, `renderLinks` (links WP),
  `renderSeo` (que chama `renderSeoSummary`, `renderSeoHeaders`,
  `renderSeoImages`, `renderSeoLinks`, `renderSeoSocial`, `renderFavicon`,
  `renderSeoHeadTable`, `renderSeoJsonLd`), helpers `addKvRow`,
  `addEmptyItem`, `subdomainUrl`.
- **Orquestração**: `buildReport()` e `runScan()` (reseta a UI, resolve
  origin, dispara as consultas independentes em paralelo, depois detecta WP
  e mostra os botões finais). Listeners de clique e de abas no final do
  arquivo.

## Design (tema visual)

Tema dark "hacker terminal", definido via CSS custom properties no topo do
`popup.css`, alinhado às cores do logo (ciano e roxo neon sobre fundo escuro):

- Popup com **420px** de largura (subiu de 340px na v1.6.0 pra caber abas e
  listas de SEO como imagens/links sem espremer).
- Fundo quase preto (`--bg: #0a0e12`) com leve glow radial verde/ciano nos
  cantos.
- Fonte monoespaçada (`--mono`, JetBrains Mono com fallbacks).
- Cor de destaque primária: verde neon (`--accent: #39ff9e`), usado em
  títulos, botões, status positivo, badges de sucesso e aba ativa.
- Cor secundária: ciano (`--cyan: #2fe0ff`), usado em links clicáveis e no
  botão Copiar relatório.
- Vermelho (`--danger`) e amarelo (`--warn`) para severidade crítica/atenção.
- Botões são outline (borda colorida, fundo transparente) e invertem cor no
  hover.
- Abas com sublinhado na cor de destaque; sub-abas como botões outline
  pequenos, ativa com fundo `--accent-dim`.
- Scrollbar customizada fina; listas longas rolam dentro do próprio bloco
  (`max-height: 320px`).
- O painel do inspetor injetado na página repete a mesma paleta, hardcoded.

## Preferências do usuário aplicadas neste projeto

- Nunca usar travessão em textos/respostas (vale pra este arquivo, README,
  UI e mensagens no chat). Usar vírgula, dois-pontos ou parênteses.
- Idioma da interface e da documentação: português (commits em inglês).
- Prefere respostas objetivas, focadas em melhoria/otimização.
- Sempre perguntar antes de commitar/dar push, e descrever o que mudou e o
  que ficou de fora.
- Quando algo não pôde ser testado de verdade, dizer isso explicitamente.

## Como validar (limitações reais)

Nunca foi possível rodar a extensão num Chrome real durante o desenvolvimento
assistido: o browser pane da ferramenta não carrega extensão MV3, não tem
`chrome.*` e renderiza HTML local sem o CSS. Então **todo o código foi
validado só estaticamente**, e o autor testa manualmente no Chrome. Checagens
usadas a cada mudança:

```bash
cd wp-link-scanner
node --check popup.js          # sintaxe
# todo getElementById do JS precisa existir no HTML (exceto ids do painel do
# inspetor: sx-breadcrumb, sx-body, sx-close, que são criados em runtime):
node -e 'const fs=require("fs");const h=fs.readFileSync("popup.html","utf8"),j=fs.readFileSync("popup.js","utf8");
console.log([...j.matchAll(/getElementById\("([^"]+)"\)/g)].map(m=>m[1]).filter(i=>!h.includes(`id="${i}"`)&&!["sx-breadcrumb","sx-body","sx-close"].includes(i)))'
node -e 'JSON.parse(require("fs").readFileSync("manifest.json","utf8"))'  # manifest válido
```

Risco conhecido: `popup.js` passa de 2000 linhas em arquivo único e sem
testes automatizados. Bug só aparece no uso real; o autor reporta e a gente
corrige. Vale testar em sites variados (WordPress, Shopify, SPA, um `http://`).

## Ideias de melhorias já discutidas e ainda não implementadas

Ordenadas por impacto x esforço:

- ~~Performance via PageSpeed Insights~~ — **feito (v1.14.0)**, botão sob demanda.
- ~~Exportar relatório em arquivo~~ — **feito (v1.13/1.14)**: `.md` e `.html`.
- ~~Histórico por domínio~~ — **feito (v1.14.0)**, `chrome.storage.local`, 20 entradas.
- ~~Badge no ícone com contagem~~ — **feito (v1.14.0)**, `chrome.action.setBadgeText` após scan.
- ~~Detecção de plugins/tema WP~~ — **feito (v1.14.0)**, paths da home.
- ~~Mixed content~~ / ~~robots.txt~~ / ~~mais tech signatures~~ — **feito (v1.14.0)**.
- ~~Não perder o scan ao fechar o popup~~ — **feito**: side panel + `chrome.storage.session`.
- Gerar o ícone em tamanhos dedicados (16/32/48) se o de 16px ficar borrado.
- Rodar scan automático em background (`background.js` + `setBadgeText`) em
  vez de só sob demanda (badge hoje só atualiza com o side panel aberto).
- Editar elemento ao vivo no inspetor (ver risco na seção Element Info).

## Como testar localmente

1. Abrir `chrome://extensions`.
2. Ativar "Modo do desenvolvedor".
3. "Carregar sem compactação" apontando pra pasta **`wp-link-scanner/`** (a
   subpasta, não a raiz do repositório: o `manifest.json` está lá dentro, e
   apontar pra raiz dá "arquivo de manifesto ausente").
4. Depois de `git pull`, um clique em recarregar costuma bastar. Ao mudar
   `manifest.json` de forma que afete permissões ou ícones (ex: a permissão
   `cookies` da v1.11.0), **remover a extensão e carregar de novo**, pra
   evitar permissão cacheada.
5. Quem baixou o ZIP do GitHub recebe a pasta `site-xray-master/` e precisa
   carregar `site-xray-master/wp-link-scanner/`.
