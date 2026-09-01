# WP Link Scanner

Extensão de navegador (Chrome, Manifest V3) que analisa o site aberto na aba
ativa e mostra, em um popup, informações públicas úteis para diagnóstico:
detecção de WordPress, links sensíveis do WP, sitemap, rastreadores/pixels de
marketing instalados na página e atalhos de consulta de domínio.

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

Versão atual do manifest: **1.3.0**.

**Sempre que uma alteração for feita no código, subir o `version` no
`manifest.json` (semver simples: patch para ajustes pequenos, minor para
novas seções/funcionalidades).**

## Funcionalidades atuais

O popup roda `runScan()` automaticamente ao abrir (`DOMContentLoaded`) e tem
um botão "Escanear novamente". As seções abaixo são **independentes entre
si** — nenhuma depende da detecção de WordPress ter dado certo, exceto a
última:

1. **Ferramentas de domínio** (sempre aparece)
   - Link para WHOIS do domínio (`who.is/whois/{hostname}`)
   - Link fixo para o sitemap padrão da raiz (`{origin}/sitemap.xml`)
   - Link para busca no Google com operador `site:{hostname}` (páginas indexadas)

2. **Sitemap** (sempre roda, independente de ser WordPress)
   - Descoberto por 3 fontes, nessa ordem de prioridade/confiabilidade:
     1. Linhas `Sitemap:` do `robots.txt`
     2. Tag `<link rel="sitemap">` no `<head>` do HTML da home
     3. Lista de caminhos padrão como fallback (`/sitemap.xml`,
        `/sitemap_index.xml`, `/sitemap-index.xml`, `/wp-sitemap.xml`,
        `/page-sitemap.xml`, `/post-sitemap.xml`)
   - Resultado deduplicado por URL, só mostra os que responderam `ok`
   - Botão "Abrir todos" (abre em abas de fundo, ver seção UX abaixo)

3. **Rastreadores e pixels na página** (sempre roda, independente de ser WordPress)
   - Usa `chrome.scripting.executeScript` com `world: "MAIN"` na aba ativa
     (não é fetch de HTML bruto — lê a página já renderizada de verdade,
     incluindo scripts injetados dinamicamente)
   - Detecta via `window.*` globals e/ou `<script src>`: Meta Pixel, Google
     Tag Manager, Google Analytics (GA4/Universal), Google Ads, TikTok Pixel,
     Pinterest Tag, Snapchat Pixel, LinkedIn Insight Tag, Twitter/X Pixel,
     Hotjar, Microsoft Clarity, Jetpack Stats, HubSpot, Matomo/Piwik, Google
     reCAPTCHA, Criteo, Taboola, Outbrain
   - Renderiza como badges simples, sem severidade (é informativo, não risco)

4. **Detecção de WordPress + links sensíveis** (só aparece se detectado)
   - Detecção: procura sinais no HTML da home (`wp-content`, `wp-includes`,
     `wp-json`, meta generator) e, como fallback, confirma direto batendo em
     `/wp-json/` e checando se a resposta JSON tem `name`/`namespaces`
   - Se detectado, testa uma lista fixa de caminhos (`CANDIDATE_PATHS`) e
     classifica cada um por **severidade**: 🔴 crítico / 🟡 atenção / 🟢 info
     - Exemplos: `wp-json/wp/v2/users` (crítico, expõe usuários — lê o JSON
       e mostra quantos e quais), `xmlrpc.php` (atenção, brute force),
       `readme.html` (atenção, tenta extrair a versão exata do WP exposta),
       `wp-content/uploads|plugins|themes` (info, mas escala pra crítico se
       detectar listagem de diretório ativa via regex `index of /` no corpo
       da resposta)
     - Lista ordenada por severidade, cada item mostra status HTTP + nota de
       risco em texto
   - Botão "Abrir todos"

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

- Botão "copiar relatório" (resumo em texto pronto pra colar em orçamento/proposta)
- Detecção de plugins e tema ativo do WordPress (via caminhos de CSS/JS
  carregados na home, ex: `wp-content/plugins/nome-do-plugin/`)
- Headers de segurança da resposta (`X-Frame-Options`, `Content-Security-Policy`,
  `Strict-Transport-Security`) — dado que já teríamos de graça, pois o fetch
  já é feito
- Checar se o site força HTTPS (testar a versão `http://` e ver se redireciona)
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
