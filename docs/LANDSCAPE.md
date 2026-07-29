# DAST & Dynamic Security Testing Landscape

A curated catalog of **382 tools** that perform some form of dynamic security testing — commercial, open source, research, abandoned and experimental. It is the research corpus behind Yubel's engine selection; Yubel wraps the strongest OSS engines here and this list documents the wider ecosystem.

> Status legend: **Ativo** = actively maintained · **Manutencao** = maintenance only · **Novo/Beta** = new/experimental · **Abandonado/Descontinuado/Arquivado** = not maintained. Columns S/N/P = Yes/No/Partial. Verify before adopting.

## Academico

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| Morest / MINER / Pythia / foREST | Diversos grupos academicos | Fuzzers REST de pesquisa | P | Diversas | Pesquisa | N | S | N | [link](https://github.com/) |
| bBOXRT | Universidade de Coimbra | Black-box robustness testing de REST | S | OSS | Pesquisa | N | S | N | [link](https://github.com/nmsa/bBOXRT) |
| Black Widow | Chalmers (Eriksson et al.) | Crawler/scanner com modelagem de estado | S | OSS | Pesquisa | S | N | N | [link](https://github.com/SecuringWeb/BlackWidow) |
| Enemy of the State | UCSB (Doupe et al.) | Scanner state-aware | P | OSS | Pesquisa | S | N | N | [link](https://github.com/adamdoupe/enemy-of-the-state) |
| jAEk / jÄk | academico | Crawler JS-aware | S | OSS | Pesquisa | S | N | N | [link](https://github.com/) |
| NAVEX | academico (Purdue) | Exploracao guiada por navegacao | P | OSS | Pesquisa | S | N | N | [link](https://github.com/) |
| Witcher | ASU (SEFCOM) | Fuzzing de aplicacoes web (SQLi/CI) | S | OSS | Pesquisa | S | P | N | [link](https://github.com/sefcom/Witcher) |
| Deemon | academico (Pellegrino et al.) | Deteccao de CSRF por modelo | S | OSS | Pesquisa | S | N | N | [link](https://github.com/) |
| VulnBot / ARACNE / HackSynth / xOffense / D-CIPHER / CHECKMATE | Grupos academicos | Agentes LLM de pentest | P | Diversas | Pesquisa | S | P | P | [link](https://github.com/) |

## Comercial

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| Digifort Inspect | Digifort | DAST | N | Comercial | Incerto | S | ? | N | [link](https://www.digifort.com.br/) |
| Vex | UBsecure (Japao) | DAST | N | Comercial | Ativo | S | P | N | [link](https://www.ubsecure.jp/vex) |
| SecPoint Penetrator | SecPoint (Dinamarca) | VA + web scan appliance | N | Comercial | Ativo | S | P | N | [link](https://www.secpoint.com/) |
| DefenseCode Web Security Scanner | DefenseCode (Croacia) | DAST | N | Comercial | Incerto | S | P | N | [link](https://www.defensecode.com/) |
| SmartScanner | SmartScanner | DAST desktop | N | Comercial (free tier) | Ativo | S | P | N | [link](https://www.thesmartscanner.com/) |
| Abbey Scan (MisterScanner) | MisterScanner | DAST SaaS | N | Comercial | Incerto | S | N | N | [link](https://misterscanner.com/) |
| Securus | Orvant | DAST | N | Comercial | Incerto | S | ? | N | [link](https://www.orvant.com/) |
| WebScanService | German Web Security | DAST gerenciado | N | Comercial | Incerto | S | N | N | [link](https://www.webscanservice.de/) |
| Cyberant Website Security Check | Cyberant | Scan pontual | N | Comercial | Incerto | S | N | N | [link](https://cyberant.com/) |
| Sucuri SiteCheck | GoDaddy/Sucuri | Scan remoto de malware/web | N | Freemium | Ativo | S | N | N | [link](https://sitecheck.sucuri.net/) |
| Quttera | Quttera | Scan de malware web | N | Freemium | Ativo | S | N | N | [link](https://quttera.com/) |
| Caido | Caido | Proxy/scanner moderno | N | Freemium | Ativo | S | S | N | [link](https://caido.io/) |
| SoapUI / ReadyAPI Security | SmartBear | Testes de seguranca SOAP/REST | P | OSS (SoapUI) + Comercial | Ativo | N | S | N | [link](https://smartbear.com/product/ready-api/) |

## Descontinuado

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| Tinfoil Security | Synopsys | DAST + API scanning | N | Comercial | Descontinuado | S | S | N | [link](https://www.synopsys.com/) |
| Cenzic Hailstorm | Cenzic | DAST | N | Comercial | Descontinuado | S | N | N | [link](https://www.trustwave.com/) |
| N-Stalker / N-Stealth | N-Stalker (BR) | DAST | N | Comercial | Descontinuado | S | N | N | [link](http://www.nstalker.com/) |
| GamaScan | GamaSec | DAST SaaS | N | Comercial | Descontinuado | S | N | N | [link](https://www.gamasec.com/) |
| Websecurify Suite / WebReaver / Proxy.app | Websecurify | DAST desktop (macOS) | N | Comercial | Descontinuado | S | P | N | [link](https://suite.websecurify.com/) |
| GitLab Proxy-based DAST | GitLab | DAST em CI (baseado em ZAP) | P | Comercial | Descontinuado | S | P | S | [link](https://docs.gitlab.com/user/application_security/dast/) |
| GitLab Coverage-guided fuzz testing | GitLab | Fuzzing em CI | P | Comercial | Descontinuado | N | S | S | [link](https://docs.gitlab.com/user/application_security/coverage_fuzzing/) |
| Fuzzit | Fuzzit | Fuzzing as a service | N | Comercial | Descontinuado | N | S | N | [link](https://about.gitlab.com/) |
| Wikto / Watcher / x5s | SensePost / Casaba | Ferramentas historicas de scan passivo/ativo | S | GPL/OSS | Descontinuado | S | N | N | [link](https://github.com/sensepost/wikto) |
| Ratproxy | Google | Proxy de auditoria passiva | S | Apache-2.0 | Descontinuado | S | N | N | [link](https://code.google.com/archive/p/ratproxy/) |
| Andiparos | Comunidade | Fork do Paros | S | Clarified Artistic | Descontinuado | S | N | N | [link](https://code.google.com/archive/p/andiparos/) |
| Zed Attack Proxy (fork Google Code) | Comunidade | Historico | S | Apache-2.0 | Descontinuado | S | N | N | [link](https://www.zaproxy.org/) |

## Descontinuado (adquirido)

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| Crashtest Security | Crashtest Security (Alemanha) | DAST dev-first | N | Comercial | Descontinuado | S | S | N | [link](https://docs.veracode.com/r/crashtest-security-suite) |

## Descontinuado (rebrand)

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| Netsparker | Netsparker Ltd | DAST | N | Comercial | Descontinuado | S | S | N | [link](https://www.invicti.com/) |
| WhiteHat Sentinel Dynamic | WhiteHat Security | DAST gerenciado | N | Comercial | Descontinuado | S | P | N | [link](https://www.blackduck.com/) |

## Descontinuado (transferido)

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| IBM Security AppScan | IBM | DAST | N | Comercial | Descontinuado | S | P | N | [link](https://www.hcl-software.com/appscan) |

## Diversos

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| Purple Knight / outros agregadores | Diversos | Agregacao | P | Diversas | Ativo | P | P | P | [link](https://www.purple-knight.com/) |

## Enterprise

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| Burp Suite DAST | PortSwigger | DAST Web/API | N | Comercial | Ativo | S | S | P | [link](https://portswigger.net/burp/dast) |
| Burp Suite Professional | PortSwigger | DAST manual/assistido | N | Comercial (US$475/ano) | Ativo | S | S | N | [link](https://portswigger.net/burp/pro) |
| Burp Suite Community | PortSwigger | Proxy/manual | N | Freeware | Ativo | P | P | N | [link](https://portswigger.net/burp/communitydownload) |
| Dastardly | PortSwigger | DAST CI/CD (lightweight) | N | Gratuito | Ativo | S | N | N | [link](https://portswigger.net/burp/dastardly) |
| Invicti (Enterprise/Standard) | Invicti Security | DAST + IAST | N | Comercial | Ativo | S | S | P | [link](https://www.invicti.com/) |
| Acunetix Premium/360 | Invicti Security | DAST | N | Comercial | Ativo | S | S | P | [link](https://www.acunetix.com/) |
| Checkmarx DAST | Checkmarx | DAST (plataforma One) | N | Comercial | Ativo | S | S | P | [link](https://checkmarx.com/product/cx-dast/) |
| HCL AppScan Standard | HCL Software | DAST desktop | N | Comercial | Ativo | S | S | N | [link](https://www.hcl-software.com/appscan) |
| HCL AppScan Enterprise | HCL Software | DAST corporativo | N | Comercial | Ativo | S | S | P | [link](https://www.hcl-software.com/appscan) |
| HCL AppScan on Cloud (ASoC) | HCL Software | DAST SaaS | N | Comercial | Ativo | S | S | P | [link](https://cloud.appscan.com/) |
| HCL AppScan 360º | HCL Software | AST containerizado | N | Comercial | Ativo | S | S | S | [link](https://www.hcl-software.com/appscan) |
| OpenText Fortify WebInspect (DAST) | OpenText | DAST | N | Comercial | Ativo | S | S | P | [link](https://www.opentext.com/products/webinspect) |
| OpenText Fortify on Demand (Dynamic) | OpenText | DAST as a Service | N | Comercial | Ativo | S | S | P | [link](https://www.opentext.com/products/fortify-on-demand) |
| Rapid7 InsightAppSec | Rapid7 | DAST cloud | N | Comercial | Ativo | S | S | P | [link](https://www.rapid7.com/products/insightappsec/) |
| Rapid7 AppSpider | Rapid7 | DAST on-prem | N | Comercial | Manutencao | S | S | N | [link](https://www.rapid7.com/products/appspider/) |
| Qualys Web Application Scanning (WAS) | Qualys | DAST cloud | N | Comercial | Ativo | S | S | P | [link](https://www.qualys.com/apps/web-app-scanning/) |
| Tenable Web App Scanning | Tenable | DAST cloud | N | Comercial | Ativo | S | S | P | [link](https://www.tenable.com/products/tenable-web-app-scanning) |
| Veracode DAST / DAST Essentials | Veracode | DAST | N | Comercial | Ativo | S | S | P | [link](https://www.veracode.com/products/dynamic-analysis-dast/) |
| Black Duck Continuous Dynamic | Black Duck (ex-Synopsys SIG) | DAST gerenciado | N | Comercial | Ativo | S | S | P | [link](https://www.blackduck.com/) |
| Black Duck Polaris (Dynamic) | Black Duck | AST unificado | N | Comercial | Ativo | S | S | P | [link](https://www.blackduck.com/polaris.html) |
| Contrast Assess / Contrast ADR | Contrast Security | IAST + runtime | N | Comercial (free 1 app) | Ativo | S | S | S | [link](https://www.contrastsecurity.com/) |
| GitLab DAST (browser-based, v5+) | GitLab | DAST em CI | P | Comercial (Ultimate) | Ativo | S | P | S | [link](https://docs.gitlab.com/user/application_security/dast/) |
| GitLab API Security / API Fuzzing | GitLab | DAST de API | N | Comercial (Ultimate) | Manutencao | N | S | S | [link](https://docs.gitlab.com/user/application_security/api_security_testing/) |
| Trustwave App Scanner | Trustwave | DAST | N | Comercial | Incerto | S | P | N | [link](https://www.trustwave.com/) |
| Outpost24 SWAT / Snapshot | Outpost24 | DAST + PTaaS | N | Comercial | Ativo | S | S | P | [link](https://outpost24.com/) |
| Edgescan | Edgescan | DAST + PTaaS + EASM | N | Comercial | Ativo | S | S | P | [link](https://www.edgescan.com/) |
| AppCheck NG | AppCheck Ltd (UK) | DAST + infra scan | N | Comercial | Ativo | S | S | P | [link](https://appcheck-ng.com/) |
| beSECURE | Fortra / Beyond Security | DAST + VA | N | Comercial | Ativo | S | P | N | [link](https://www.beyondsecurity.com/) |
| beSTORM | Fortra / Beyond Security | Fuzzer de protocolo (black-box) | N | Comercial | Ativo | P | S | N | [link](https://www.beyondsecurity.com/solutions/bestorm.html) |
| Black Duck Defensics | Black Duck (ex-Synopsys) | Fuzzer de protocolo | N | Comercial | Ativo | P | S | N | [link](https://www.blackduck.com/fuzz-testing.html) |
| ImmuniWeb On-Demand / Discovery | ImmuniWeb (ex-High-Tech Bridge) | DAST + AI + pentest | N | Comercial | Ativo | S | S | P | [link](https://www.immuniweb.com/) |
| Indusface WAS / AppTrana | Indusface | DAST + WAF | N | Comercial | Ativo | S | S | N | [link](https://www.indusface.com/) |
| Holm Security VMP (Web App Scanning) | Holm Security | VA + web scanning | N | Comercial | Ativo | S | P | P | [link](https://www.holmsecurity.com/) |
| Cycode ASPM (DAST integrado) | Cycode | ASPM | N | Comercial | Ativo | P | P | S | [link](https://cycode.com/) |
| Nucleus Security | Nucleus | Agregacao/orquestracao VM | N | Comercial | Ativo | P | P | S | [link](https://nucleussec.com/) |
| Data Theorem Web Secure / API Secure | Data Theorem | DAST web/API/mobile | N | Comercial | Ativo | S | S | S | [link](https://www.datatheorem.com/) |
| Pentera | Pentera | Validacao de seguranca automatizada | N | Comercial | Ativo | S | P | S | [link](https://pentera.io/) |
| CyCognito | CyCognito | EASM com testes ativos | N | Comercial | Ativo | S | P | P | [link](https://www.cycognito.com/) |
| Bishop Fox Cosmos | Bishop Fox | EASM + pentest continuo | N | Comercial | Ativo | S | P | P | [link](https://bishopfox.com/platform) |
| IBM Randori Recon | IBM | EASM com testes | N | Comercial | Ativo | S | P | P | [link](https://www.ibm.com/products/randori-recon) |
| Cobalt PTaaS | Cobalt.io | Pentest como servico | N | Comercial | Ativo | S | S | P | [link](https://www.cobalt.io/) |
| HackerOne (Pentest/Hai) | HackerOne | PTaaS + bug bounty | N | Comercial | Ativo | S | S | P | [link](https://www.hackerone.com/) |
| Bugcrowd Pen Test as a Service | Bugcrowd | PTaaS + bug bounty | N | Comercial | Ativo | S | S | P | [link](https://www.bugcrowd.com/) |
| Synack | Synack | PTaaS + rede de pesquisadores | N | Comercial | Ativo | S | S | P | [link](https://www.synack.com/) |
| BreachLock | BreachLock | PTaaS + DAST | N | Comercial | Ativo | S | S | P | [link](https://www.breachlock.com/) |
| Picus Security | Picus | BAS | N | Comercial | Ativo | P | P | S | [link](https://www.picussecurity.com/) |
| Cymulate | Cymulate | BAS + exposure validation | N | Comercial | Ativo | P | P | S | [link](https://cymulate.com/) |
| SafeBreach | SafeBreach | BAS | N | Comercial | Ativo | P | N | S | [link](https://www.safebreach.com/) |
| AttackIQ | AttackIQ | BAS | N | Comercial | Ativo | P | N | S | [link](https://www.attackiq.com/) |
| Greenbone Enterprise | Greenbone | VA comercial | P | Comercial | Ativo | P | N | P | [link](https://www.greenbone.net/) |
| Nessus / Nessus Expert | Tenable | VA + web app scanning | N | Comercial | Ativo | P | P | P | [link](https://www.tenable.com/products/nessus) |
| Rapid7 Nexpose / InsightVM | Rapid7 | VA | N | Comercial | Ativo | P | N | S | [link](https://www.rapid7.com/products/insightvm/) |
| Salt Security | Salt Security | API runtime + posture testing | N | Comercial | Ativo | N | S | S | [link](https://salt.security/) |
| Traceable AI (API Security Testing) | Traceable (Harness) | API DAST + runtime | N | Comercial | Ativo | N | S | S | [link](https://www.traceable.ai/) |
| Akamai API Security (ex-Noname) | Akamai | API posture + testing | N | Comercial | Ativo | N | S | S | [link](https://www.akamai.com/products/api-security) |
| Cequence Unified API Protection | Cequence | API testing + protecao | N | Comercial | Ativo | N | S | S | [link](https://www.cequence.ai/) |
| Wallarm API Security Testing (FAST) | Wallarm | API DAST a partir de trafego | P | Comercial | Ativo | S | S | S | [link](https://www.wallarm.com/) |
| Mayhem for API / Mayhem | Mayhem Security (ex-ForAllSecure) | Fuzzing de API e binarios | N | Comercial | Ativo | N | S | S | [link](https://www.mayhem.security/) |
| Deepfence ThreatStryker | Deepfence | Protecao/testes runtime | N | Comercial | Ativo | P | P | S | [link](https://deepfence.io/) |
| NodeZero Kubernetes Pentest | Horizon3.ai | Pentest autonomo de K8s | N | Comercial | Ativo | P | S | S | [link](https://horizon3.ai/) |
| Aqua / Prisma Cloud / Wiz / Orca / Lacework (CNAPP) | Diversos | CNAPP com testes de exposicao | N | Comercial | Ativo | P | P | S | [link](https://www.wiz.io/) |
| NowSecure Platform | NowSecure | DAST mobile | N | Comercial | Ativo | P | S | P | [link](https://www.nowsecure.com/) |
| Corellium | Corellium | Virtualizacao ARM para testes dinamicos | N | Comercial | Ativo | N | S | N | [link](https://www.corellium.com/) |
| Invicti / Acunetix plugins (Jenkins, Azure DevOps, TeamCity, Bamboo) | Invicti | DAST em CI | N | Comercial | Ativo | S | S | N | [link](https://www.invicti.com/support/) |
| Qualys WAS CI/CD plugins (Jenkins/Azure DevOps/Bamboo) | Qualys | DAST em CI | N | Comercial | Ativo | S | S | P | [link](https://www.qualys.com/documentation/) |
| Checkmarx One CLI/plugins | Checkmarx | AST em CI e IDE | N | Comercial | Ativo | S | S | S | [link](https://checkmarx.com/) |
| Burp Suite DAST Jenkins/TeamCity plugins | PortSwigger | DAST em CI | N | Comercial | Ativo | S | S | S | [link](https://portswigger.net/burp/documentation/enterprise) |

## Freemium

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| Xray (chaitin) | Chaitin Tech (China) | Scanner web/PoC | N | Binario gratuito/Comercial | Ativo | S | P | N | [link](https://github.com/chaitin/xray) |
| Goby | Chaitin / Zhengxin | Asset mapping + PoC scan | N | Gratuito/Comercial | Ativo | S | P | P | [link](https://gobies.org/) |
| Sn1per | 1N3 / Xerosecurity | Framework de pentest automatizado | P | OSS + Pro | Ativo | S | P | P | [link](https://github.com/1N3/Sn1per) |
| Ostorlab | Ostorlab | Scanner mobile/web/API | P | Apache-2.0 (OXO) + SaaS | Ativo | S | S | S | [link](https://github.com/Ostorlab/oxo) |

## Incerto

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| SecApps / Websecurify online | SecApps | Suite web de testes | N | Freemium | Incerto | S | P | N | [link](https://secapps.com/) |

## OSS

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| Mozilla HTTP Observatory | Mozilla / MDN | Scan de configuracao HTTP/TLS | S | MPL-2.0 | Ativo | S | N | N | [link](https://developer.mozilla.org/en-US/observatory) |
| ZAP (Zed Attack Proxy) | ZAP Dev Team / Checkmarx | DAST completo | S | Apache-2.0 | Ativo | S | S | S | [link](https://www.zaproxy.org/) |
| ZAP Extensions (add-ons) | ZAP Dev Team | Add-ons DAST | S | Apache-2.0 | Ativo | S | S | P | [link](https://github.com/zaproxy/zap-extensions) |
| ZAP Community Scripts | ZAP Dev Team | Scripts de scan | S | Apache-2.0 | Ativo | S | S | N | [link](https://github.com/zaproxy/community-scripts) |
| Nuclei | ProjectDiscovery | Scanner por templates | S | MIT | Ativo | S | S | S | [link](https://github.com/projectdiscovery/nuclei) |
| Nuclei Templates | ProjectDiscovery + comunidade | Base de assinaturas | S | MIT | Ativo | S | S | S | [link](https://github.com/projectdiscovery/nuclei-templates) |
| Nikto2 | CIRT.net (Sullo) | Scanner de servidor web | S | GPL-2.0 | Ativo | S | N | N | [link](https://github.com/sullo/nikto) |
| Wapiti | Nicolas Surribas / comunidade | DAST black-box | S | GPL-2.0 | Ativo | S | P | N | [link](https://wapiti-scanner.github.io/) |
| w3af | Andres Riancho | Framework DAST | S | GPL-2.0 | Abandonado | S | P | N | [link](http://w3af.org/) |
| Arachni | Ecsypno / Tasos Laskos | Framework DAST | S | Arachni Public Source License | Descontinuado | S | P | N | [link](https://www.arachni-scanner.com/) |
| Vega | Subgraph | DAST GUI | S | EPL | Abandonado | S | N | N | [link](https://subgraph.com/vega/) |
| Skipfish | Google (Michal Zalewski) | Scanner ativo | S | Apache-2.0 | Arquivado | S | N | N | [link](https://code.google.com/archive/p/skipfish/) |
| Grabber | Romain Gaucher | Scanner didatico | S | OSS | Abandonado | S | N | N | [link](https://github.com/neuroo/grabber) |
| GoLismero | GoLismero Team | Framework de scan | S | GPL-2.0 | Abandonado | S | N | N | [link](https://github.com/golismero/golismero) |
| Grendel-Scan | David Byrne | DAST Java | S | GPL | Abandonado | S | N | N | [link](https://sourceforge.net/projects/grendel/) |
| IronWASP | Lavakumar Kuppan | Framework DAST | S | OSS | Abandonado | S | N | N | [link](https://ironwasp.org/) |
| OWASP WebScarab | OWASP | Proxy/scanner | S | GPL | Abandonado | S | N | N | [link](https://owasp.org/www-project-webscarab/) |
| Paros Proxy | Chinotec | Proxy/scanner | S | Clarified Artistic | Abandonado | S | N | N | [link](https://sourceforge.net/projects/paros/) |
| Sitadel (ex-WAScan) | shenril | Scanner web | S | GPL-3.0 | Manutencao | S | N | N | [link](https://github.com/shenril/Sitadel) |
| WAScan | m4ll0k | Scanner web | S | GPL-3.0 | Abandonado | S | N | N | [link](https://github.com/m4ll0k/WAScan) |
| Taipan | enkomio | Scanner web (F#/.NET) | S | OSS | Manutencao | S | N | N | [link](https://github.com/enkomio/Taipan) |
| Striker | s0md3v | Recon + scan ofensivo | S | GPL-3.0 | Manutencao | S | N | N | [link](https://github.com/s0md3v/Striker) |
| Spaghetti | m4ll0k | Scanner web | S | GPL-3.0 | Manutencao | S | N | N | [link](https://github.com/m4ll0k/Spaghetti) |
| RapidScan | skavngr | Meta-scanner | S | GPL-3.0 | Manutencao | S | P | N | [link](https://github.com/skavngr/rapidscan) |
| OSTE-Meta-Scan | OSTEsayed | Meta-scanner DAST | S | OSS | Ativo | S | P | N | [link](https://github.com/OSTEsayed/OSTE-Meta-Scan) |
| OWASP Nettacker | OWASP | Framework de recon/scan | S | Apache-2.0 | Ativo | S | P | P | [link](https://github.com/OWASP/Nettacker) |
| OWASP ASST | OWASP (Ismail Tasdelen et al.) | Scanner web (PHP/MySQL) | S | OSS | Manutencao | S | N | N | [link](https://github.com/OWASP/ASST) |
| OWASP purpleteam | OWASP | DAST orientado a CI (SaaS-like) | S | Apache-2.0 | Manutencao | S | S | S | [link](https://owasp.org/www-project-purpleteam/) |
| OWASP OFFAT | OWASP (Dhrumil Mistry) | OFFensive Api Tester | S | MIT | Ativo | N | S | P | [link](https://github.com/OWASP/OFFAT) |
| OWASP Noir | OWASP (hahwul) | Descoberta de endpoints (attack surface) | S | MIT | Ativo | S | S | P | [link](https://github.com/owasp-noir/noir) |
| OWASP JoomScan | OWASP | Scanner Joomla | S | GPL-3.0 | Manutencao | S | N | N | [link](https://github.com/OWASP/joomscan) |
| OWASP Amass | OWASP | Descoberta de superficie | S | Apache-2.0 | Ativo | P | P | P | [link](https://github.com/owasp-amass/amass) |
| Hetty | Sander Rademaker (dstotijn) | Proxy HTTP para pesquisa | S | MIT | Manutencao | S | P | N | [link](https://hetty.xyz/) |
| mitmproxy | mitmproxy team | Proxy programavel | S | MIT | Ativo | S | S | S | [link](https://mitmproxy.org/) |
| Reaper | Ghost Security | Plataforma de teste web | S | OSS | Ativo | S | S | N | [link](https://ghostsecurity.github.io/reaper/) |
| Pakiki (Pākiki) | Forensant | Proxy/scanner | S | AGPL/Comercial | Ativo | S | P | N | [link](https://github.com/forensant/pakiki-core) |
| ProKZee | al-sultani | Proxy/intercepcao | S | OSS | Novo | S | P | N | [link](https://github.com/al-sultani/prokzee) |
| BrowserBruter | NetSquare (Bhargav Rathod) | Fuzzing via browser | S | OSS | Ativo | S | N | N | [link](https://github.com/netsquare/BrowserBruter) |
| Tulpar | tulpar | Scanner web | S | GPL | Abandonado | S | N | N | [link](https://github.com/tulpar/tulpar) |
| Ugly Duckling | Detectify | Scanner modular | S | Apache-2.0 | Manutencao | S | N | N | [link](https://github.com/detectify/ugly-duckling) |
| Jawfish | war-and-code | Scanner web | S | OSS | Abandonado | S | N | N | [link](https://github.com/war-and-code/jawfish) |
| Browserker | GitLab (wirepair) | Crawler/DAST browser-based | P | Proprietary/GitLab | Manutencao | S | P | N | [link](https://gitlab.com/wirepair/browserker/) |
| Sasori | karthikuj | Crawler dinamico (Puppeteer) | S | MIT | Ativo | S | P | N | [link](https://github.com/karthikuj/sasori) |
| Moxy | matank001 | DAST agentico | S | OSS | Novo | S | S | N | [link](https://github.com/matank001/Moxy) |
| Vigolium | vigolium | Scanner agentico (IA + Go) | S | OSS | Novo | S | S | P | [link](https://github.com/vigolium/vigolium) |
| Dark-Moon | ASCIT31 | Engine de pentest autonomo | S | OSS | Novo | S | S | S | [link](https://github.com/ASCIT31/Dark-Moon) |
| numasec | FrancescoStabile | Agente de seguranca (IA) | S | OSS | Novo | S | S | P | [link](https://github.com/FrancescoStabile/numasec) |
| secpipe | FuzzingLabs | MCP server para pipelines de seguranca IA | S | OSS | Novo | S | S | P | [link](https://github.com/FuzzingLabs/secpipe) |
| HexStrike AI | 0x4m4 | Orquestrador MCP (150+ ferramentas) | S | OSS | Ativo | S | S | S | [link](https://github.com/0x4m4/hexstrike-ai) |
| SecOpsAgentKit | AgentSecOps | Toolkit de seguranca para agentes | S | OSS | Novo | S | S | S | [link](https://github.com/AgentSecOps/SecOpsAgentKit) |
| poc-runner | 4ra1n | Engine de PoC (regras XRAY YAML) | S | OSS | Ativo | S | N | N | [link](https://github.com/4ra1n/poc-runner) |
| afrog | zan8in | Scanner de vulnerabilidades | S | MIT | Ativo | S | P | N | [link](https://github.com/zan8in/afrog) |
| scan4all | GhostTroops | Scanner all-in-one | S | GPL-3.0 | Ativo | S | P | P | [link](https://github.com/GhostTroops/scan4all) |
| Pocsuite3 | Knownsec 404 Team | Framework de PoC/exploit | S | GPL-2.0 | Ativo | S | P | N | [link](https://github.com/knownsec/pocsuite3) |
| POC-bomber | tr0uble-mAker | Framework de PoCs de alto impacto | S | OSS | Manutencao | S | P | N | [link](https://github.com/tr0uble-mAker/POC-bomber) |
| POC-T | Xyntax | Framework de concorrencia para PoCs | S | OSS | Manutencao | S | P | N | [link](https://github.com/Xyntax/POC-T) |
| vulmap | zhzyker | Scanner/exploit web | S | MIT | Manutencao | S | P | N | [link](https://github.com/zhzyker/vulmap) |
| Jaeles | jaeles-project (j3ssie) | Framework de scan por assinaturas | S | MIT | Manutencao | S | P | N | [link](https://github.com/jaeles-project/jaeles) |
| Osmedeus | j3ssie | Workflow engine de recon/scan | S | MIT | Ativo | S | P | P | [link](https://github.com/j3ssie/osmedeus) |
| Tsunami Security Scanner | Google | Scanner de superficie com plugins | S | Apache-2.0 | Ativo | S | P | S | [link](https://github.com/google/tsunami-security-scanner) |
| OpenVAS / Greenbone Community Edition | Greenbone | VA de rede + checks web | S | GPL-2.0 | Ativo | P | N | P | [link](https://github.com/greenbone/openvas-scanner) |
| Metasploit Framework (aux/web) | Rapid7 + comunidade | Exploracao/verificacao | S | BSD-3 | Ativo | P | P | P | [link](https://github.com/rapid7/metasploit-framework) |
| Ladon | k8gege | Scanner de rede interna | S | OSS | Ativo | P | N | N | [link](https://github.com/k8gege/Ladon) |
| Vuls | Future Architect | VA agentless | S | GPL-3.0 | Ativo | N | N | S | [link](https://github.com/future-architect/vuls) |
| Raccoon | evyatarmeged | Recon + VA ofensivo | S | MIT | Manutencao | S | P | N | [link](https://github.com/evyatarmeged/Raccoon) |
| Akto Community Edition | Akto | API DAST OSS | S | MIT/AGPL (ver repo) | Ativo | N | S | S | [link](https://github.com/akto-api-security/community-edition) |
| GoTestWAF | Wallarm | Teste dinamico de WAF/API gateway | S | Apache-2.0 | Ativo | S | S | S | [link](https://github.com/wallarm/gotestwaf) |
| Metlo | Metlo Labs (YC) | Plataforma OSS de API security | S | MIT (ver repo) | Incerto/Manutencao | N | S | S | [link](https://github.com/metlo-labs/metlo) |
| Cherrybomb | BLST Security | Auditoria de spec + testes de API | S | Apache-2.0 | Manutencao | N | S | N | [link](https://github.com/blst-security/cherrybomb) |
| VulnAPI | CerberAuth | Scanner de vulnerabilidades de API | S | MIT | Ativo | N | S | P | [link](https://github.com/cerberauth/vulnapi) |
| APIKit | API-Security (China) | Descoberta + scan + auditoria de API | S | OSS | Ativo | N | S | N | [link](https://github.com/API-Security/APIKit) |
| Automatic API Attack Tool | Imperva | Gerador de ataques a partir de spec | S | MIT | Manutencao | N | S | N | [link](https://github.com/imperva/automatic-api-attack-tool) |
| Astra (Flipkart) | Flipkart Incubator | REST API security testing | S | Apache-2.0 | Abandonado | N | S | N | [link](https://github.com/flipkart-incubator/Astra) |
| APIFuzzer | KissPeter | Fuzzer de OpenAPI/Swagger | S | GPL-3.0 | Manutencao | N | S | N | [link](https://github.com/KissPeter/APIFuzzer) |
| CATS | Endava (Madalin Ilie) | REST API fuzzer/negative testing | S | Apache-2.0 | Ativo | N | S | N | [link](https://github.com/Endava/cats) |
| RESTler | Microsoft Research | Fuzzer stateful de REST | S | MIT | Manutencao | N | S | P | [link](https://github.com/microsoft/restler-fuzzer) |
| fuzz-lightyear | Yelp | DAST de API (chaos/statefulness) | S | MIT | Abandonado | N | S | N | [link](https://github.com/Yelp/fuzz-lightyear) |
| TnT-Fuzzer | Teebytes | Fuzzer OpenAPI 2.0 | S | MIT | Abandonado | N | S | N | [link](https://github.com/Teebytes/TnT-Fuzzer) |
| WuppieFuzz | TNO (Holanda) | Fuzzer REST coverage-guided | S | Apache-2.0 | Ativo | N | S | N | [link](https://github.com/TNO-S3/WuppieFuzz) |
| REST-Attacker | Uni Hamburg (RUB) | Framework de testes REST/OAuth | S | MIT | Manutencao | N | S | N | [link](https://github.com/RUB-NDS/REST-Attacker) |
| fuzzapi / API_Fuzzer | Lucideus | Fuzzer de API (Ruby gem) | S | MIT | Abandonado | N | S | N | [link](https://github.com/Fuzzapi/fuzzapi) |
| Schemathesis | Dmitry Dygalo | Property-based API testing (OpenAPI/GraphQL) | S | MIT | Ativo | N | S | P | [link](https://github.com/schemathesis/schemathesis) |
| Dredd | Apiary/Oracle | Teste de contrato de API | S | MIT | Manutencao | N | S | N | [link](https://github.com/apiaryio/dredd) |
| Step CI | Step CI | Testes de REST/GraphQL/gRPC | S | MPL-2.0 | Manutencao | N | S | P | [link](https://github.com/stepci/stepci) |
| WS-Attacker | RUB-NDS (Alemanha) | Framework de ataque a Web Services (SOAP) | S | GPL-2.0 | Abandonado | N | S | N | [link](https://github.com/RUB-NDS/WS-Attacker) |
| WSSAT | YalcinYolalan | Web Service Security Assessment Tool | S | Apache-2.0 | Abandonado | N | S | N | [link](https://github.com/YalcinYolalan/WSSAT) |
| InQL | Doyensec | Testes de GraphQL (Burp ext + CLI) | S | Apache-2.0 | Ativo | N | S | N | [link](https://github.com/doyensec/inql) |
| GraphQLmap | Swissky | Engine de exploracao GraphQL | S | MIT | Manutencao | N | S | N | [link](https://github.com/swisskyrepo/GraphQLmap) |
| graphql-cop | Dolev Farhi | Auditor de seguranca GraphQL | S | MIT | Ativo | N | S | N | [link](https://github.com/dolevf/graphql-cop) |
| graphw00f | Dolev Farhi | Fingerprint de engine GraphQL | S | BSD | Ativo | N | S | N | [link](https://github.com/dolevf/graphw00f) |
| graphql-threat-matrix | Nick Aleks | Matriz de ameacas GraphQL | S | MIT | Ativo | N | S | N | [link](https://github.com/nicholasaleks/graphql-threat-matrix) |
| CrackQL | Nick Aleks | Brute-force/fuzzing GraphQL | S | MIT | Manutencao | N | S | N | [link](https://github.com/nicholasaleks/CrackQL) |
| BatchQL | Assetnote | Auditor de batching GraphQL | S | MIT | Manutencao | N | S | N | [link](https://github.com/assetnote/batchql) |
| clairvoyance | nikitastupin | Recupera schema GraphQL sem introspection | S | Apache-2.0 | Ativo | N | S | N | [link](https://github.com/nikitastupin/clairvoyance) |
| goctopus | Escape | Descoberta de endpoints GraphQL | S | Apache-2.0 | Manutencao | N | S | N | [link](https://github.com/Escape-Technologies/goctopus) |
| gqlspection / GraphQL Raider | Doyensec / Burp BApp | Extensoes GraphQL para Burp | S | OSS | Ativo | N | S | N | [link](https://portswigger.net/bappstore) |
| grpcurl | FullStory | Cliente/reflexao gRPC | S | MIT | Ativo | N | S | S | [link](https://github.com/fullstorydev/grpcurl) |
| grpc-scan / grpc_tools scanners | Comunidade | Enumeracao gRPC | S | OSS | Manutencao | N | S | S | [link](https://github.com/nxenon/grpc-pentest-suite) |
| STEWS | Palindrome Technologies | Security Testing/Enumeration of WebSockets | S | MIT | Manutencao | N | S | N | [link](https://github.com/PalindromeLabs/STEWS) |
| wsrepl | Doyensec | REPL interativo para WebSocket | S | Apache-2.0 | Ativo | N | S | N | [link](https://github.com/doyensec/wsrepl) |
| WebSocket Turbo Intruder | PortSwigger | Fuzzing de WebSocket | S | OSS (BApp) | Ativo | N | S | N | [link](https://portswigger.net/bappstore) |
| Arjun | s0md3v | Descoberta de parametros HTTP | S | AGPL-3.0 | Ativo | S | S | N | [link](https://github.com/s0md3v/Arjun) |
| kiterunner | Assetnote | Descoberta de rotas de API | S | AGPL-3.0 | Manutencao | N | S | N | [link](https://github.com/assetnote/kiterunner) |
| ffuf | joohoi | Fuzzer HTTP rapido | S | MIT | Ativo | S | S | N | [link](https://github.com/ffuf/ffuf) |
| wfuzz | Xmendez | Fuzzer web | S | GPL-2.0 | Manutencao | S | S | N | [link](https://github.com/xmendez/wfuzz) |
| feroxbuster | epi052 | Descoberta de conteudo recursiva | S | MIT | Ativo | S | P | N | [link](https://github.com/epi052/feroxbuster) |
| dirsearch | maurosoria | Descoberta de caminhos | S | GPL-2.0 | Ativo | S | P | N | [link](https://github.com/maurosoria/dirsearch) |
| gobuster | OJ Reeves | Brute-force de diretorios/DNS/vhost | S | Apache-2.0 | Ativo | S | P | N | [link](https://github.com/OJ/gobuster) |
| dirb / DirBuster | OWASP | Descoberta de conteudo | S | GPL | Abandonado | S | N | N | [link](https://github.com/v0re/dirb) |
| rustbuster | phra | Fuzzer/brute-forcer | S | MIT | Abandonado | S | P | N | [link](https://github.com/phra/rustbuster) |
| vaf | d4rckh | Fuzzer web rapido | S | MIT | Manutencao | S | P | N | [link](https://github.com/d4rckh/vaf) |
| radamsa | Aki Helin (OUSPG) | Fuzzer mutacional generico | S | MIT | Ativo | P | S | N | [link](https://gitlab.com/akihe/radamsa) |
| boofuzz | Joshua Pereyda | Framework de fuzzing de rede | S | GPL-2.0 | Ativo | N | S | S | [link](https://github.com/jtpereyda/boofuzz) |
| Sulley | OpenRCE | Framework de fuzzing | S | GPL | Abandonado | N | S | N | [link](https://github.com/OpenRCE/sulley) |
| Fuzzowski | moongift/nccgroup | Fuzzer de protocolo de rede | S | GPL-2.0 | Manutencao | N | S | N | [link](https://github.com/nccgroup/fuzzowski) |
| AFL++ | AFLplusplus team | Fuzzer coverage-guided | S | Apache-2.0 | Ativo | N | P | S | [link](https://github.com/AFLplusplus/AFLplusplus) |
| honggfuzz | Google (Robert Swiecki) | Fuzzer | S | Apache-2.0 | Ativo | N | P | S | [link](https://github.com/google/honggfuzz) |
| LibAFL | AFLplusplus team | Framework de fuzzing modular | S | Apache/MIT | Ativo | N | S | S | [link](https://github.com/AFLplusplus/LibAFL) |
| sqlmap | sqlmap project (Bernardo/Miroslav) | Exploracao de SQL Injection | S | GPL-2.0 | Ativo | S | S | N | [link](https://sqlmap.org/) |
| Ghauri | r0oth3x49 | SQLi automatizado | S | MIT | Ativo | S | S | N | [link](https://github.com/r0oth3x49/ghauri) |
| NoSQLMap | codingo | Ataques a NoSQL/MongoDB | S | GPL-3.0 | Manutencao | S | S | N | [link](https://github.com/codingo/NoSQLMap) |
| XSStrike | s0md3v | Deteccao/exploracao de XSS | S | GPL-3.0 | Manutencao | S | P | N | [link](https://github.com/s0md3v/XSStrike) |
| Dalfox | hahwul | Scanner/parametro de XSS | S | MIT | Ativo | S | S | N | [link](https://github.com/hahwul/dalfox) |
| XSpear | hahwul | Scanner XSS (Ruby) | S | MIT | Manutencao | S | P | N | [link](https://github.com/hahwul/XSpear) |
| kxss / Gxss | Tom Hudson / KathanP19 | Deteccao de reflexao XSS | S | MIT | Manutencao | S | N | N | [link](https://github.com/tomnomnom/hacks) |
| Commix | Anastasios Stasinopoulos | Command injection | S | GPL-3.0 | Ativo | S | S | N | [link](https://github.com/commixproject/commix) |
| tplmap | epinna | SSTI (Server-Side Template Injection) | S | GPL-3.0 | Abandonado | S | S | N | [link](https://github.com/epinna/tplmap) |
| SSTImap | vladko312 | SSTI moderno | S | GPL-3.0 | Ativo | S | S | N | [link](https://github.com/vladko312/SSTImap) |
| Fuxploider | almandin | Upload de arquivos malicioso | S | GPL-3.0 | Manutencao | S | P | N | [link](https://github.com/almandin/fuxploider) |
| SSRFmap | swisskyrepo | Exploracao de SSRF | S | MIT | Manutencao | S | S | S | [link](https://github.com/swisskyrepo/SSRFmap) |
| Gopherus | tarunkant | Payloads SSRF -> Gopher | S | MIT | Manutencao | S | S | N | [link](https://github.com/tarunkant/Gopherus) |
| interactsh | ProjectDiscovery | OAST (out-of-band) | S | MIT | Ativo | S | S | S | [link](https://github.com/projectdiscovery/interactsh) |
| Smuggler / h2csmuggler | defparam / BishopFox | HTTP Request Smuggling | S | MIT | Manutencao | S | S | S | [link](https://github.com/defparam/smuggler) |
| CRLFuzz | dwisiswant0 | CRLF injection | S | MIT | Manutencao | S | P | N | [link](https://github.com/dwisiswant0/crlfuzz) |
| Corsy | s0md3v | Misconfiguracao de CORS | S | GPL-3.0 | Manutencao | S | S | N | [link](https://github.com/s0md3v/Corsy) |
| Oralyzer | r0075h3ll | Open redirect | S | MIT | Manutencao | S | P | N | [link](https://github.com/r0075h3ll/Oralyzer) |
| jwt_tool | ticarpi | Ataques a JWT | S | GPL-3.0 | Ativo | S | S | N | [link](https://github.com/ticarpi/jwt_tool) |
| Autorize / AuthMatrix / Auth Analyzer | Burp BApps | Testes de autorizacao (IDOR/BOLA) | S | OSS | Ativo | S | S | N | [link](https://portswigger.net/bappstore) |
| Nuclei DAST templates (fuzzing) | ProjectDiscovery | Fuzzing de parametros por template | S | MIT | Ativo | S | S | S | [link](https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview) |
| Retire.js | Erlend Oftedal | Deteccao de libs JS vulneraveis (runtime) | S | Apache-2.0 | Ativo | S | N | N | [link](https://retirejs.github.io/retire.js/) |
| BurpBounty (Scan Check Builder) | wagiro | Regras de scan ativo customizadas | S | GPL-3.0 | Ativo | S | S | N | [link](https://github.com/wagiro/BurpBounty) |
| ActiveScan++ | PortSwigger (albinowax) | Checks adicionais no Burp | S | OSS | Ativo | S | S | N | [link](https://portswigger.net/bappstore) |
| Backslash Powered Scanner | PortSwigger (albinowax) | Deteccao de vulns desconhecidas | S | OSS | Ativo | S | S | N | [link](https://portswigger.net/bappstore) |
| Param Miner | PortSwigger | Descoberta de parametros/headers ocultos | S | OSS | Ativo | S | S | N | [link](https://portswigger.net/bappstore) |
| Turbo Intruder | PortSwigger | Fuzzing HTTP de alta velocidade | S | OSS | Ativo | S | S | N | [link](https://github.com/PortSwigger/turbo-intruder) |
| J2EEScan | IMQ Minded Security | Checks Java/J2EE no Burp | S | OSS | Manutencao | S | P | N | [link](https://github.com/ilmila/J2EEScan) |
| Freddy (Deserialization) | NCC Group | Deteccao de desserializacao insegura | S | OSS | Manutencao | S | S | N | [link](https://github.com/nccgroup/freddy) |
| PTK (Penetration Testing Kit) | OWASP / DenisPodgurskii | Extensao de browser para AppSec | S | OSS | Ativo | S | S | N | [link](https://github.com/DenisPodgurskii/pentestkit) |
| droopescan | SamJoan | Scanner Drupal/SilverStripe/WP | S | AGPL-3.0 | Manutencao | S | N | N | [link](https://github.com/SamJoan/droopescan) |
| CMSeeK | Tuhinshubhra | Deteccao/scan de CMS | S | GPL-3.0 | Manutencao | S | N | N | [link](https://github.com/Tuhinshubhra/CMSeeK) |
| CMSScan | Ajin Abraham | Scanner de CMS (wrapper) | S | GPL-3.0 | Manutencao | S | N | N | [link](https://github.com/ajinabraham/CMSScan) |
| Vulnx | anouarbensaad | Scanner/exploiter de CMS | S | GPL-3.0 | Manutencao | S | N | N | [link](https://github.com/anouarbensaad/vulnx) |
| Drupwn | immunIT | Scanner Drupal | S | MIT | Manutencao | S | N | N | [link](https://github.com/immunIT/drupwn) |
| clusterd | hatRiot | Ataque a application servers | S | OSS | Abandonado | S | N | N | [link](https://github.com/hatRiot/clusterd) |
| Magescan | steverobbins | Scanner Magento | S | MIT | Abandonado | S | N | N | [link](https://github.com/steverobbins/magescan) |
| plecost | iniqua | Scanner de plugins WordPress | S | BSD | Abandonado | S | N | N | [link](https://github.com/iniqua/plecost) |
| WPProbe | Chocapikk | Enumeracao rapida de plugins WP | S | MIT | Ativo | S | N | N | [link](https://github.com/Chocapikk/WPProbe) |
| crawlergo | Qianlitp | Crawler headless para scanners | S | OSS | Manutencao | S | P | N | [link](https://github.com/Qianlitp/crawlergo) |
| katana | ProjectDiscovery | Crawler moderno (headless) | S | MIT | Ativo | S | S | S | [link](https://github.com/projectdiscovery/katana) |
| gospider / hakrawler | jaeles-project / hakluke | Crawlers rapidos | S | MIT | Manutencao | S | P | N | [link](https://github.com/jaeles-project/gospider) |
| httpx | ProjectDiscovery | Probing HTTP em escala | S | MIT | Ativo | S | S | S | [link](https://github.com/projectdiscovery/httpx) |
| Playwright / Puppeteer (custom DAST) | Microsoft / Google | Automacao de browser para testes | S | Apache-2.0 / Apache-2.0 | Ativo | S | P | S | [link](https://playwright.dev/) |
| Selenium/WebDriver | Selenium | Automacao de browser | S | Apache-2.0 | Ativo | S | N | S | [link](https://www.selenium.dev/) |
| wsltools | Symbo1 | Toolkit Python para scan web | S | OSS | Manutencao | S | P | N | [link](https://github.com/Symbo1/wsltools) |
| kube-hunter | Aqua Security | Pentest dinamico de cluster K8s | S | Apache-2.0 | Manutencao/Arquivado | N | S | S | [link](https://github.com/aquasecurity/kube-hunter) |
| Peirates | InGuardians | Exploracao de Kubernetes | S | Apache-2.0 | Ativo | N | S | S | [link](https://github.com/inguardians/peirates) |
| kubesploit | CyberArk | C2/pentest para containers | S | GPL-3.0 | Manutencao | N | S | S | [link](https://github.com/cyberark/kubesploit) |
| KubiScan | CyberArk | Analise de RBAC arriscado | S | GPL-3.0 | Manutencao | N | S | S | [link](https://github.com/cyberark/KubiScan) |
| Kubestriker | Vasant Kumar Chinnipilli | Pentest de K8s | S | Apache-2.0 | Manutencao | N | S | S | [link](https://github.com/vchinnipilli/kubestriker) |
| CDK (Container DucK) | cdk-team | Toolkit de escape de container | S | Apache-2.0 | Ativo | N | S | S | [link](https://github.com/cdk-team/CDK) |
| Break out the Box (BOtB) | brompwnie | Escape de container | S | Apache-2.0 | Manutencao | N | S | S | [link](https://github.com/brompwnie/botb) |
| deepce | stealthcopter | Docker enumeration & escalation | S | GPL-3.0 | Manutencao | N | S | S | [link](https://github.com/stealthcopter/deepce) |
| amicontained | Jess Frazelle | Introspeccao de sandbox de container | S | MIT | Manutencao | N | P | S | [link](https://github.com/genuinetools/amicontained) |
| kdigger | quarkslab | Toolkit de descoberta em pods | S | Apache-2.0 | Ativo | N | S | S | [link](https://github.com/quarkslab/kdigger) |
| Deepfence ThreatMapper | Deepfence | Descoberta + scan de runtime cloud native | S | Apache-2.0 | Ativo | P | P | S | [link](https://github.com/deepfence/ThreatMapper) |
| Stratus Red Team | DataDog | Emulacao de ataques cloud | S | Apache-2.0 | Ativo | N | P | S | [link](https://github.com/DataDog/stratus-red-team) |
| Halberd | Vectra AI | Emulacao multi-cloud de ataques | S | Apache-2.0 | Ativo | N | P | S | [link](https://github.com/vectra-ai-research/Halberd) |
| Pacu | Rhino Security Labs | Framework de exploracao AWS | S | BSD-3 | Ativo | N | P | S | [link](https://github.com/RhinoSecurityLabs/pacu) |
| Leonidas | F-Secure/WithSecure | Framework de simulacao de ataques cloud | S | Apache-2.0 | Manutencao | N | P | S | [link](https://github.com/WithSecureLabs/leonidas) |
| ScoutSuite / Prowler / CloudSploit | NCC Group / Prowler / Aqua | CSPM (posture, nao DAST) | S | GPL/Apache | Ativo | N | N | S | [link](https://github.com/prowler-cloud/prowler) |
| nginxpwner | stark0de | Teste de misconfig do Nginx | S | OSS | Manutencao | S | N | S | [link](https://github.com/stark0de/nginxpwner) |
| Kubernetes Goat / OWASP WrongSecrets / crAPI / Juice Shop / DVWA / VAmPI / WebGoat | Comunidade/OWASP | Alvos de laboratorio | S | MIT/Apache/GPL | Ativo | S | S | S | [link](https://owasp.org/www-project-juice-shop/) |
| OWASP Benchmark / ant-application-security-testing-benchmark | OWASP / Alipay | Benchmarks para AST | S | Apache-2.0 | Ativo | S | S | N | [link](https://github.com/alipay/ant-application-security-testing-benchmark) |
| MobSF (Dynamic Analyzer) | Ajin Abraham | Analise dinamica mobile + API | S | GPL-3.0 | Ativo | P | S | P | [link](https://github.com/MobSF/Mobile-Security-Framework-MobSF) |
| Frida / Objection | Ole Andre Ravnas / SensePost | Instrumentacao dinamica | S | wxWindows/GPL | Ativo | P | S | N | [link](https://frida.re/) |
| RouterSploit | Threat9 | Exploracao de dispositivos embarcados | S | BSD-3 | Manutencao | P | N | N | [link](https://github.com/threat9/routersploit) |
| EMBA | EMBA team (Siemens Energy) | Analise de firmware (estatica+dinamica) | S | GPL-3.0 | Ativo | P | P | N | [link](https://github.com/e-m-b-a/emba) |
| FirmAE / Firmadyne | pr0v3rbs / firmadyne | Emulacao dinamica de firmware | S | MIT/OSS | Manutencao | P | P | N | [link](https://github.com/pr0v3rbs/FirmAE) |
| expliot | EXPLIoT | Framework de pentest IoT | S | AGPL-3.0 | Manutencao | P | S | N | [link](https://gitlab.com/expliot_framework/expliot) |
| mqtt-pwn / MQTTSA | akamai-threat-research / academico | Teste dinamico de brokers MQTT | S | MIT/OSS | Manutencao | N | S | S | [link](https://github.com/akamai-threat-research/mqtt-pwn) |
| smod / Modbus fuzzers | enddo e outros | Teste de ICS/Modbus | S | GPL | Abandonado | N | S | N | [link](https://github.com/enddo/smod) |
| Sweyntooth / BtleJuice / Gattacker | academico / DigitalSecurity | Testes dinamicos BLE | S | MIT/GPL | Manutencao | N | S | N | [link](https://github.com/DigitalSecurity/btlejuice) |
| Mercedes-Benz SecHub | Mercedes-Benz Tech Innovation | API central para orquestrar scanners | S | MIT | Ativo | S | S | S | [link](https://github.com/mercedes-benz/sechub) |
| DefectDojo | OWASP / DefectDojo Inc | ASPM/agregacao de achados | S | BSD-3 | Ativo | S | S | S | [link](https://github.com/DefectDojo/django-DefectDojo) |
| ArcherySec | ArcherySec | Orquestracao SAST/DAST | S | Apache-2.0 | Manutencao | S | P | P | [link](https://github.com/archerysec/archerysec) |
| ThreatPlaybook | we45 | Threat modeling as code + orquestracao DAST | S | MIT | Abandonado | S | S | N | [link](https://github.com/we45/ThreatPlaybook) |
| SecObserve | MaibornWolff | Gestao de achados (OSS) | S | BSD-3 | Ativo | S | S | S | [link](https://github.com/MaibornWolff/SecObserve) |
| Dracon | Ocurity/OWASP | Pipeline de seguranca cloud-native | S | Apache-2.0 | Manutencao | S | S | S | [link](https://github.com/ocurity/dracon) |
| Jackhammer | Olacabs | Orquestrador de scanners | S | MIT | Abandonado | S | P | N | [link](https://github.com/olacabs/jackhammer) |
| OWASP Glue | OWASP | Cola entre scanners e CI | S | Apache-2.0 | Abandonado | S | P | N | [link](https://github.com/OWASP/glue) |
| Reapsaw | Dow Jones | Pipeline DevSecOps | S | Apache-2.0 | Abandonado | S | P | N | [link](https://github.com/dowjones/reapsaw) |
| ZAP GitHub Actions (baseline/full-scan/api-scan) | ZAP Dev Team | DAST em GitHub Actions | S | Apache-2.0 | Ativo | S | S | S | [link](https://github.com/zaproxy/action-full-scan) |
| Dastardly GitHub Action | PortSwigger | DAST em CI | S | Gratuito | Ativo | S | N | N | [link](https://github.com/PortSwigger/dastardly-github-action) |
| ZAP Jenkins Plugin / official-zap | Comunidade Jenkins | DAST em Jenkins | S | MIT | Manutencao | S | S | N | [link](https://plugins.jenkins.io/zap/) |
| OWASP ZAP Azure DevOps extension | Comunidade | DAST em Azure Pipelines | S | MIT | Manutencao | S | S | N | [link](https://marketplace.visualstudio.com/) |
| StackHawk GitHub Action / CircleCI orb | StackHawk | DAST em CI | S | Apache-2.0 | Ativo | S | S | S | [link](https://github.com/marketplace/actions/stackhawk-hawkscan-action) |
| Bright Security GitHub App / bright-cli | Bright Security | DAST em CI/CD | S | MIT (CLI) | Ativo | S | S | S | [link](https://github.com/NeuraLegion/bright-cli) |
| Nuclei GitHub Action | ProjectDiscovery | Scan por templates em CI | S | MIT | Ativo | S | S | S | [link](https://github.com/projectdiscovery/nuclei-action) |
| SecureStack actions-exposure / actions-all-in-one | SecureStack | Scan pos-deploy em CI | S | OSS | Manutencao | S | P | S | [link](https://github.com/SecureStackCo/actions-exposure) |
| Trivy/Grype/Checkov/Terrascan | Aqua/Anchore/Bridgecrew/Tenable | Scanners estaticos (delimitacao) | S | Apache-2.0 | Ativo | N | N | S | [link](https://github.com/aquasecurity/trivy) |
| CAI (Cybersecurity AI) | Alias Robotics | Framework de agentes ofensivos | S | MIT | Ativo | S | S | S | [link](https://github.com/aliasrobotics/cai) |
| Strix | Strix | Plataforma agentica de pentest | S | Apache-2.0 | Novo | S | S | P | [link](https://github.com/usestrix/strix) |
| PentAGI | vxcontrol | Multi-agente autonomo | S | MIT | Novo | S | S | P | [link](https://github.com/vxcontrol/pentagi) |
| NeuroSploit | CyberSecurityUP (Joas Santos, BR) | Agentes de pentest em container | S | MIT | Novo | S | S | P | [link](https://github.com/CyberSecurityUP/NeuroSploit) |
| Raptor | Gadi Evron et al. | Pentest agentico nativo em Claude Code | S | OSS | Novo | S | S | P | [link](https://github.com/) |
| DeepAudit | lintsinghua | Multi-agente para descoberta de vulns | S | OSS | Novo | P | P | N | [link](https://github.com/lintsinghua/DeepAudit) |
| claude-bug-bounty | shuvonsec | Workflow de bug bounty com IA | S | OSS | Novo | S | S | N | [link](https://github.com/shuvonsec/claude-bug-bounty) |

## OSS/Academico

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| EvoMaster | Andrea Arcuri (Kristiania/Oslo Met) | Geracao evolutiva de testes de API | S | LGPL-3.0 | Ativo | N | S | N | [link](https://github.com/WebFuzzing/EvoMaster) |
| RESTest | Universidad de Sevilla | Geracao automatica de testes REST | S | Apache-2.0 | Manutencao | N | S | N | [link](https://github.com/isa-group/RESTest) |
| RestTestGen | Universita di Napoli | Testes automatizados de REST | S | Apache-2.0 | Manutencao | N | S | N | [link](https://github.com/SeUniVr/RestTestGen) |
| PentestGPT | GreyDGL (NTU) | Agente LLM para pentest | S | MIT | Ativo | S | S | P | [link](https://github.com/GreyDGL/PentestGPT) |
| hackingBuddyGPT | IPA Lab (Austria) | Agente LLM minimalista | S | MIT | Ativo | S | P | P | [link](https://github.com/ipa-lab/hackingBuddyGPT) |
| Atlantis / Buttercup / ARTIPHISHELL | Team Atlanta / Trail of Bits / Shellphish | Sistemas de ciber-raciocinio (DARPA AIxCC) | S | Diversas (OSS pos-AIxCC) | Ativo | P | P | S | [link](https://github.com/trailofbits/buttercup) |

## OSS/Comercial

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| SSL Labs / testssl.sh | Qualys / Dirk Wetter | Teste dinamico de TLS | P | GPL-2.0 (testssl.sh) | Ativo | S | S | S | [link](https://testssl.sh/) |
| Peach Fuzzer (Community) | Peach Tech / GitLab | Fuzzer de protocolo | P | MPL/Comercial | Descontinuado | P | S | N | [link](https://gitlab.com/gitlab-org/security-products/protocol-fuzzer-ce) |
| Wappalyzer / WhatWeb | Wappalyzer / urbanadventurer | Fingerprint de tecnologias | P | GPL-2.0 (WhatWeb) | Ativo | S | P | N | [link](https://github.com/urbanadventurer/WhatWeb) |
| Faraday | Faraday Security (Argentina) | Plataforma colaborativa de pentest/VM | P | GPL-3.0 + Comercial | Ativo | S | S | S | [link](https://github.com/infobyte/faraday) |

## OSS/Freemium

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| WPScan | WPScan (Automattic) | Scanner WordPress | S | GPL-3.0 (CLI) + API paga | Ativo | S | N | N | [link](https://github.com/wpscanteam/wpscan) |

## Startup

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| HostedScan Security | HostedScan | VA/DAST gerenciado (OSS por baixo) | N | Comercial (free tier) | Ativo | S | P | N | [link](https://hostedscan.com/) |
| ScanRepeat | Ventures CDX | DAST SaaS | N | Comercial | Incerto | S | P | N | [link](https://scanrepeat.com/) |
| ScanTitan | ScanTitan | DAST SaaS | N | Comercial | Incerto | S | P | N | [link](https://www.scantitan.com/) |
| Security For Everyone (s4e) | Security For Everyone | Scanners agregados | P | Freemium | Ativo | S | P | N | [link](https://securityforeveryone.com/) |
| ReconwithMe | Nassec | DAST SaaS | N | Comercial | Incerto | S | P | N | [link](https://reconwithme.com/) |
| IOTHREAT | IOTHREAT | Scan para startups | N | Comercial | Incerto | S | N | N | [link](https://iothreat.com/) |
| CloudDefense.ai | CloudDefense | CNAPP com DAST | N | Comercial | Ativo | S | S | S | [link](https://www.clouddefense.ai/) |
| Aikido Security (DAST/Surface Monitoring) | Aikido | ASPM/CNAPP com DAST | N | Comercial (free tier) | Ativo | S | S | S | [link](https://www.aikido.dev/scanners/surface-monitoring-dast) |
| Ox Security | Ox Security | ASPM com DAST orquestrado | N | Comercial | Ativo | S | S | S | [link](https://www.ox.security/) |
| Xygeni | Xygeni | ASPM/supply chain + DAST parceiro | N | Comercial | Ativo | P | P | S | [link](https://xygeni.io/) |
| Jit.io | Jit | Orquestrador DevSecOps (ZAP/Nuclei) | N | Comercial (free tier) | Ativo | S | P | S | [link](https://www.jit.io/) |
| StackHawk | StackHawk | DAST dev-first (baseado em ZAP) | P | Comercial (free tier) | Ativo | S | S | S | [link](https://www.stackhawk.com/) |
| Bright Security (ex-NeuraLegion Nexploit) | Bright Security | DAST/API dev-first | P | Comercial (free tier) | Ativo | S | S | S | [link](https://brightsec.com/) |
| Probely | Probely (Portugal) | DAST SaaS API-first | N | Comercial | Ativo | S | S | P | [link](https://probely.com/) |
| Beagle Security | Beagle Security (India) | DAST + AI | N | Comercial (free tier) | Ativo | S | S | P | [link](https://beaglesecurity.com/) |
| Astra Security (Pentest Suite) | Astra Security (India) | DAST + PTaaS | N | Comercial | Ativo | S | S | P | [link](https://www.getastra.com/) |
| Intruder | Intruder Ltd (UK) | VA/EASM + web scanning | N | Comercial | Ativo | S | P | P | [link](https://www.intruder.io/) |
| Pentest-Tools.com | Pentest-Tools.com (Romenia) | Scanners hospedados | N | Comercial (free tier) | Ativo | S | P | N | [link](https://pentest-tools.com/) |
| Cyber Chief | Audacix (Australia) | DAST dev-first | N | Comercial | Ativo | S | S | P | [link](https://audacix.com/) |
| Autonoma AI | Autonoma | DAST agentico | N | Comercial | Novo/Beta | S | S | P | [link](https://getautonoma.com/) |
| Stingrai | Stingrai | Pentest continuo com IA | N | Comercial | Novo/Beta | S | S | P | [link](https://www.stingrai.io/) |
| Ethiack | Ethiack (Portugal) | Hacking autonomo + humano | N | Comercial | Ativo | S | S | P | [link](https://www.ethiack.com/) |
| Horizon3.ai NodeZero | Horizon3.ai | Pentest autonomo | N | Comercial | Ativo | S | P | S | [link](https://horizon3.ai/) |
| Terra Security | Terra Security | Pentest web agentico | N | Comercial | Ativo | S | S | P | [link](https://www.terra.security/) |
| RunSybil | RunSybil | Pentest autonomo | N | Comercial | Novo | S | S | N | [link](https://runsybil.com/) |
| Mindfort | Mindfort | AI pentest agentico | N | Comercial | Novo | S | S | N | [link](https://mindfort.ai/) |
| Hadrian | Hadrian (Holanda) | EASM + validacao ofensiva | N | Comercial | Ativo | S | P | P | [link](https://hadrian.io/) |
| Sprocket Security | Sprocket | Pentest continuo | N | Comercial | Ativo | S | P | P | [link](https://www.sprocketsecurity.com/) |
| Equixly | Equixly (Italia) | API pentest continuo | N | Comercial | Ativo | N | S | P | [link](https://equixly.com/) |
| Escape (escape.tech) | Escape | DAST de API + business logic | N | Comercial | Ativo | S | S | S | [link](https://escape.tech/) |
| 42Crunch API Security Platform | 42Crunch | Conformance scan + protecao | N | Comercial (free tier) | Ativo | N | S | S | [link](https://42crunch.com/) |
| APIsec.ai | APIsec | API pentest automatizado | N | Comercial (free tier) | Ativo | N | S | P | [link](https://www.apisec.ai/) |
| Aptori | Aptori | API DAST semantico + AI | N | Comercial | Ativo | N | S | S | [link](https://aptori.dev/) |
| Pynt | Pynt | API security testing dev-first | P | Freemium | Ativo | N | S | P | [link](https://www.pynt.io/) |
| Levo.ai | Levo | Descoberta + testes de API | N | Comercial | Ativo | N | S | S | [link](https://www.levo.ai/) |
| Firetail | Firetail | API security posture + testes | N | Comercial (free tier) | Ativo | N | S | S | [link](https://www.firetail.ai/) |
| Akto (Enterprise) | Akto | Descoberta + testes de API | P | Comercial + OSS CE | Ativo | N | S | S | [link](https://www.akto.io/) |
| Code Intelligence CI Fuzz / CI Spark | Code Intelligence (Alemanha) | Fuzzing de aplicacao e API | P | Comercial + OSS (Jazzer/cifuzz) | Ativo | N | S | S | [link](https://www.code-intelligence.com/) |
| Fuzzbuzz | Fuzzbuzz | Fuzzing as a service | N | Comercial | Descontinuado | N | S | N | [link](https://fuzzbuzz.io/) |
| Appknox | Appknox | DAST mobile | N | Comercial | Ativo | P | S | N | [link](https://www.appknox.com/) |
| Quixxi | Quixxi | Scan mobile | N | Freemium | Ativo | P | S | N | [link](https://quixxi.com/) |

## Startup (unicornio)

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| XBOW | XBOW | Pentest ofensivo autonomo (IA) | N | Comercial | Ativo | S | S | P | [link](https://xbow.com/) |

## Startup/Scale-up

| Tool | Vendor/Author | Category | OSS | License | Status | Web | API | Cloud/K8s | Link |
|---|---|---|:--:|---|---|:--:|:--:|:--:|---|
| Detectify | Detectify | EASM + App Scanning | N | Comercial | Ativo | S | P | N | [link](https://detectify.com/) |
