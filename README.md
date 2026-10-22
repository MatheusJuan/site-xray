# SiteXray

Extensão de navegador (Chrome, Manifest V3) que analisa o site aberto na aba
ativa e mostra, num popup organizado em abas, informações públicas úteis
para diagnóstico rápido: detecção de WordPress, links sensíveis, sitemap,
rastreadores de marketing, tecnologia usada no site, segurança, SEO on-page
e um inspetor visual de elementos.

Feita pra quem atende clientes de sites (freelancer, agência) e precisa
analisar rapidamente o site de um cliente ou prospect antes de uma proposta,
sem abrir dez ferramentas diferentes.

## O que tem

**Sempre visível**
- Ferramentas de domínio: WHOIS (via registro.br), DNS Checker, sitemap
  padrão e busca no Google com `site:`
- Botão "Gerar relatório" no topo: copia o relatório com um prompt pronto pra colar numa IA, que devolve os ajustes por prioridade e o impacto de cada um
- Botões de relatório no rodapé: Copiar texto, baixar `.md` e baixar `.html` (com logo)
- Badge no ícone da extensão com a contagem de achados críticos/atenção
- Botão "Dev": mostra a versão instalada, link do repositório e avisa
  quando existe uma versão mais nova disponível

**Aba Stack**
- Tecnologias detectadas no estilo Wappalyzer: ~7600 tecnologias (CMS,
  e-commerce, frameworks, bibliotecas, CDN, hospedagem, analytics, chat,
  pagamentos, e-mail e mais), com versão, categoria, ícone e confiança. A
  base de padrões é baixada do fork comunitário `enthec/webappanalyzer` e
  atualizada a cada 7 dias
- Meta Pixel: Pixel IDs, eventos disparados na página (PageView, Purchase…
  com valor, dados do usuário e event_id) e diagnóstico de instalação
- Google: containers do GTM, eventos do dataLayer, tags GA4/UA/Google Ads,
  hits de coleta, Consent Mode e alertas (page_view duplicado, UA
  descontinuado, gtag.js junto com GTM)
- Outros pixels: TikTok, Hotjar, Clarity, LinkedIn e afins

**Aba Visão Geral**
- Sitemap, descoberto via `robots.txt`, tag `<link rel="sitemap">` e
  caminhos padrão
- robots.txt: Disallow/Allow, Host e Crawl-delay
- Tema e plugins WordPress detectados pelos caminhos da home
- Integrações e widgets: pagamentos (Mercado Pago, Stripe, PagBank…),
  chat (WhatsApp, Tidio, Tawk…), CRM, maps, captcha
- Contato e privacidade: e-mails na página e links de política/termos (LGPD)
- E-mail (MX, SPF, DMARC) via DNS-over-HTTPS — sem terminal
- Bots de IA no robots.txt e presença de /llms.txt
- PageSpeed Insights sob demanda (nota mobile/desktop do Google, 10–30s)
- Histórico de scans do domínio (compara datas; não duplica se o scan
  repetir em menos de 2 min com a mesma nota)
- Detecção de WordPress, com lista de links sensíveis classificados por
  severidade (crítico / atenção / info)

**Aba Segurança**
- Nota de segurança A–F (0–100) no topo da aba
- Presença dos headers de segurança (`Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`) — inclui headers vindos só em
  redirects (HSTS em 307 etc.) e uma sonda same-origin na própria página
  quando o fetch da extensão esconde o HSTS
- Qualidade da CSP (unsafe-inline/eval, wildcard em script-src)
- Headers avançados COOP/CORP/COEP (recomendados, sem descontar da nota)
- Se o site força redirecionamento de `http://` para `https://`
- Mixed content: recursos `http://` em página `https://`
- Arquivos sensíveis expostos (`.env`, `.git`, backups, `phpinfo.php` etc.),
  validando o conteúdo pra evitar falso positivo em sites SPA
- Cookies do site com as flags `Secure`, `HttpOnly` e `SameSite` (nunca
  lê o valor)
- Parâmetros de redirect nos links internos, como candidatos a Open Redirect

Tudo passivo: a extensão não faz teste de exploração.

**Aba SEO**
- Resumo: title, description, canonical, robots meta, headings, contagem
  de imagens e links
- Headers: árvore de H1 a H6 na ordem da página
- Imagens: quais estão sem ALT ou sem title
- Links: todos os links da página, com status HTTP dos internos (achando
  link quebrado ou redirecionamento)
- Social: tags Open Graph e Twitter Card

**Aba Element Info**
- Inspetor visual de elemento: passa o mouse pra destacar, clica pra fixar
  e ver DOM, layout, posição, texto e cores do elemento selecionado, com
  botão de copiar em cada bloco

## Como instalar

1. Baixe ou clone este repositório
2. Abra `chrome://extensions` no navegador
3. Ative o "Modo do desenvolvedor" (canto superior direito)
4. Clique em "Carregar sem compactação"
5. Selecione a pasta `wp-link-scanner/` (não a raiz do repositório)

Depois de um `git pull`, um clique em recarregar na extensão já basta na
maioria das vezes. Quando o `manifest.json` muda (nova permissão, ícone
novo), é melhor remover a extensão e carregar de novo, pra evitar cache de
permissão antiga.

## Como usar

1. Abra o site que quer analisar
2. Clique no ícone da extensão na barra do navegador
3. O scan roda sozinho ao abrir o painel lateral e refaz ao trocar de aba ou navegar
4. Navegue pelas abas (Visão Geral, Segurança, SEO, Element Info)
5. Clique em "Gerar relatório" (topo) e cole numa IA pra receber os ajustes e impactos, ou use os botões do rodapé: Copiar, baixar `.md` ou baixar `.html`

## Stack

Vanilla JS, sem build step, sem dependências externas de código. Só HTML, CSS
e JS puro rodando como painel lateral de extensão Manifest V3. A única coisa
baixada em runtime é a base de padrões de tecnologias (dado, não código) do
fork comunitário do Wappalyzer, guardada localmente por 7 dias.

## Estrutura

```
wp-link-scanner/
├── manifest.json
├── popup.html
├── popup.css
├── popup.js
├── tech-engine.js
├── tracking.js
├── background.js
└── icons/
    ├── icon.png
    └── logo.png
```

Documentação técnica mais detalhada (decisões de arquitetura, cada
funcionalidade explicada por dentro) está em [CLAUDE.md](CLAUDE.md).
