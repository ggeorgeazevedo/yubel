# Yubel — kit de lançamento

Tudo pronto pra copiar/colar. Ajuste os trechos pessoais pra soar como você.

**Imagens (em `docs/logo/`):**
- `yubel-social.png` (1200×630) — capa/preview de link. Boa pro LinkedIn e X.
- `yubel-howitworks.png` (1200×680) — diagrama "como funciona". Ótimo como 2ª imagem/carrossel, ou no topo do Reddit/HN comment.
- `yubel-logo.png` / `yubel-logo-dark.png` — logo (claro/escuro).

**Links canônicos:**
- Repo: https://github.com/ggeorgeazevedo/yubel
- PyPI: https://pypi.org/project/yubel/
- Marketplace: https://github.com/marketplace/actions/yubel-dast-orchestrator

---

## 1) LinkedIn (português) — post principal

> Anexe as DUAS imagens: `yubel-social.png` (1ª) e `yubel-howitworks.png` (2ª). Posts com carrossel de imagem rendem mais.

**Lancei a Yubel: um orquestrador de DAST open-source com "cérebro de correlação". 🛡️**

Toda ferramenta de scanner de segurança te entrega uma pilha de findings. Aí você passa horas cruzando na mão: "o ZAP viu isso, o Nuclei viu aquilo — é a mesma coisa? Isso aqui, junto com aquilo, vira um ataque real?"

Foi por isso que construí a **Yubel**.

Ela não reinventa scanner nenhum. Ela **orquestra os melhores engines open-source** — ZAP, Nuclei, Nikto, testssl.sh, dalfox, sqlmap, schemathesis, kube-hunter e mais — contra **web, APIs REST/GraphQL, cloud, containers e Kubernetes**, e faz o que nenhum scanner sozinho faz:

🔗 **Correlaciona** — findings vistos por 2+ engines viram um só, corroborado
⛓️ **Sintetiza cadeias de ataque** — ex.: SSRF + metadata endpoint = "takeover da instância", não dois alertas soltos
🌐 **Correlação sistêmica entre alvos** — a mesma falha em N serviços vira 1 recomendação "corrija na origem"
🧾 **Rastro de evidência determinístico** — cada finding carrega um "por que acreditamos nisso" auditável

E o diferencial que mais me importava: **enquanto o mercado corre pra colocar LLM pra "validar" vulnerabilidade, a Yubel vai na direção oposta.** Sem LLM. Sem cloud. Zero chamadas externas — seus resultados nunca saem do perímetro. Modo `--offline` de primeira classe pra rede air-gapped/on-prem, onde ferramenta com IA não entra. Mesma varredura, mesmo resultado, sempre.

Está tudo aberto e distribuído em três canais:
📦 `pip install yubel` · 🐳 `ghcr.io/ggeorgeazevedo/yubel` · 🧩 GitHub Marketplace

👉 github.com/ggeorgeazevedo/yubel

Se você trabalha com AppSec/DevSecOps, ia adorar seu feedback — e uma ⭐ ajuda demais o projeto a crescer.

**Pergunta:** validação de vulnerabilidade por LLM — atalho útil ou risco de resultado não-reproduzível em auditoria? 👇

#DevSecOps #AppSec #DAST #CyberSecurity #OpenSource #Kubernetes #CICD

---

## 2) X / Twitter — thread (inglês)

> Anexe `yubel-howitworks.png` no tweet 1 e `yubel-social.png` no último. Threads seguram atenção melhor que 1 tweet só.

**1/**
Every DAST scanner hands you a pile of findings and leaves the hard part to you: which ones are the same issue, and which ones *chain* into a real attack.

So I built Yubel — an open-source DAST orchestrator with a correlation brain. 🧵

**2/**
It doesn't reinvent scanning. It runs best-of-breed OSS engines — ZAP, Nuclei, Nikto, testssl.sh, dalfox, sqlmap, schemathesis, kube-hunter — across web, APIs, cloud, containers & Kubernetes, and normalizes everything into one model.

**3/**
Then it does what no single scanner can:
• Consensus — 2+ engines agree → corroborated
• Attack chains — SSRF + metadata endpoint → instance takeover
• Systemic correlation — same flaw on N targets → 1 "fix centrally"
• Deterministic evidence trail — auditable "why"

**4/**
The deliberate choice: while everyone's bolting LLMs onto DAST to "validate" findings, Yubel goes the other way.

No LLM. No cloud. Zero outbound calls. First-class `--offline` for air-gapped/regulated networks. Same scan → same result, every time.

**5/**
Open-source (Apache-2.0), three ways to run:
• `pip install yubel`
• `docker run ghcr.io/ggeorgeazevedo/yubel`
• GitHub Action in the Marketplace

⭐ + feedback hugely appreciated:
https://github.com/ggeorgeazevedo/yubel

#DevSecOps #AppSec #DAST #infosec

---

## 3) r/netsec — post (inglês)

> Título e corpo. r/netsec valoriza substância técnica — lidere pelo diferencial, não pelo "eu lancei". Cole o diagrama como imagem no primeiro comentário.

**Título:**
Yubel — an open-source DAST orchestrator that correlates engine output into attack chains (deterministic, no LLM, air-gapped-friendly)

**Corpo:**
Every scanner hands you a pile of findings and leaves the correlation to you — figuring out which are duplicates and which ones chain into a real attack path.

Yubel orchestrates best-of-breed OSS engines (ZAP, Nuclei, Nikto, testssl.sh, dalfox, sqlmap, schemathesis, kube-hunter, …) across web, REST/GraphQL APIs, cloud, containers and Kubernetes, normalizes their output into one model, and adds a correlation layer:

- **Cross-engine consensus** — findings seen by 2+ engines merge into one corroborated result
- **Attack-chain synthesis** — e.g. SSRF + reachable metadata endpoint → "instance takeover", not two disconnected alerts
- **Systemic correlation across targets** — the same weakness on N services becomes one "fix centrally" finding
- **Deterministic evidence trail** — every finding carries a reproducible "why we believe this" (engines, corroboration, OWASP/CWE/MITRE, risk score)

Deliberate design choice: instead of adding an LLM to "validate" findings, the core makes **zero outbound calls** and has a first-class `--offline` mode for air-gapped / regulated / on-prem environments. Same scan, same result, every time — which matters for audit reproducibility.

Apache-2.0. Runs via `pip`, Docker (GHCR) or as a GitHub Action.

Repo: https://github.com/ggeorgeazevedo/yubel

Happy to discuss the correlation-rule design and the OWASP/CWE/MITRE mapping — feedback and PRs welcome.

---

## 4) Hacker News — Show HN (inglês)

**Título:**
Show HN: Yubel – open-source DAST orchestrator that correlates engines, no LLM

**Corpo (primeiro comentário):**
Hi HN. I built Yubel because every DAST scanner gives you a pile of findings and leaves the correlation to you.

Yubel wraps best-of-breed OSS engines (ZAP, Nuclei, Nikto, testssl.sh, dalfox, sqlmap, schemathesis, kube-hunter) across web, APIs, cloud, containers and Kubernetes, normalizes their output, and then correlates: cross-engine consensus, attack-chain synthesis (e.g. SSRF + metadata endpoint → instance takeover), systemic correlation across targets, and a deterministic "why we believe this" evidence trail.

The design bet is the opposite of the current trend: no LLM, no cloud, zero outbound calls, first-class `--offline` mode — so results are reproducible and it runs in air-gapped/regulated networks.

Apache-2.0. `pip install yubel`, Docker image on GHCR, or a GitHub Action.
https://github.com/ggeorgeazevedo/yubel

Would love feedback on the correlation rules and taxonomy mapping.

---

## Checklist de lançamento (ordem sugerida)

1. **Grava um GIF** de 10-15s do `yubel scan` rodando (terminal). Post com vídeo/GIF > imagem > só texto.
   - `asciinema rec demo.cast` → roda o scan → `agg demo.cast demo.gif` (ou um screen-record simples).
2. **Fixa o repo** no teu perfil do GitHub (aba perfil → Customize your pins → Yubel).
3. **LinkedIn (PT)** com as 2 imagens. Publica ter–qui de manhã. Responde os comentários na 1ª hora.
4. **X/Twitter (EN)** — a thread, com imagem no 1º e no último tweet.
5. **r/netsec (EN)** — foca no técnico; sem tom de auto-promo. Diagrama no 1º comentário.
6. **Show HN** — título curto, corpo no 1º comentário, fica disponível pra responder dúvidas.
7. Opcional: **dev.to / blog** com um post longo "por que construí a Yubel" (posso escrever depois).

**Dica de engajamento:** a pergunta sobre "LLM na validação" é isca de comentário — tema quente em AppSec e convida os dois lados. Comentário pesa mais que like nos algoritmos.
