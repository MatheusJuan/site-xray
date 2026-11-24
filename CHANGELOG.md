# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
versões em [SemVer](https://semver.org/lang/pt-BR/).

## [1.18.1]
- Pasta da extensão renomeada de `wp-link-scanner/` para `sitexray/`.
- Docs corrigidas: a interface é um painel lateral, não um popup.
- Adicionados `LICENSE` (MIT) e este `CHANGELOG.md`.

## [1.18.0]
- Análise leve automática (só lê a página aberta) separada da análise completa sob clique.
- O que não foi verificado aparece como "não verificado"; a nota de segurança fica "parcial".

## [1.17.0]
- Aba Stack: motor de tecnologias no formato Wappalyzer (fork enthec, baixado em runtime).
- Visão detalhada de Meta Pixel, GTM, GA4/UA e Google Ads, com diagnóstico.

## [1.16.0]
- Botão "Gerar relatório" (prompt pronto para IA) e ações movidas para o topo.

## [1.15.0] a [1.13.0]
- MX/SPF/DMARC via DoH, análise de CSP, integrações, contato/LGPD, bots de IA e `llms.txt`.
- PageSpeed Insights sob demanda, histórico por domínio, badge no ícone, plugins/tema WP,
  mixed content, robots.txt, export `.md` e `.html`, nota de segurança A a F.
- Correção do HSTS em redirects.

## [1.12.0]
- Side panel, cache por origem, Web Vitals, impacto de terceiros.

## [1.11.0] e anteriores
- Checagens passivas de segurança, tags `<head>`, JSON-LD, favicon, subdomínios via crt.sh,
  inspetor de elementos, SEO on-page, fingerprint de tecnologia e detecção de WordPress.
  Detalhe por versão e commit em `CLAUDE.md` (Histórico de versões).
