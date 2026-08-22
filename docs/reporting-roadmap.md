# Yubel — roadmap de relatoria & evidência

Benchmark contra **Invicti**, **Checkmarx DAST**, o **OWASP API Security Testing
Framework (ASTF)** e a onda de **DAST com IA** (Escape, Bright, Burp AI,
StackHawk), com foco no que você pediu: **evidência de *onde* está a falha +
como corrigir**, e onde a OpenAI/LLM entra sem quebrar o DNA determinístico/air-gapped da Yubel.

---

## 1. O que os grandes fazem (o alvo)

**Invicti — "Proof-Based Scanning"**
- Explora a falha de forma **segura e não-destrutiva (read-only)** e anexa uma **prova de exploração** — request/response + evidência extra — que confirma que *não* é falso positivo (alegam 99,98% de acurácia no confirmado).
- Cada finding rotulado **confirmado vs não-confirmado**; só o confirmado vira ticket automático (verificação → ticket → atribuição ao dev).
- **Re-teste automático de correção** ("fixed issues stay fixed"); risk scoring preditivo já na descoberta.

**Checkmarx DAST (Checkmarx One)**
- **Correlação SAST × DAST × API** num inventário único — o DAST confirma o que o SAST apontou (menos ruído, mais confiança).
- **Mapeamento de compliance** (finding → framework regulatório).
- Auth por **gravação de browser** com 2FA/MFA; relatório granular por resultado.

**OWASP API Security Testing Framework (ASTF)**
- Schema de finding padronizado: `id, title, severity, testCaseId, endpoint, **evidence**, **recommendation**`.
- 16 test cases mapeados 1:1 ao **OWASP API Top 10 2023**; teste de **multi-identidade** (BOLA/IDOR trocando token), **mTLS**, **ReDoS**, **GraphQL DoS**, canário de **prompt injection**.
- **Matriz de rastreabilidade** — documenta o que detecta *e o que erra* contra alvos reais (crAPI, VAmPI, DVGA). Honestidade = credibilidade.
- Guidelines de remediação por categoria.

**DAST com IA (Escape, Bright, Burp AI, StackHawk)**
- IA para **validação de exploit** antes do ticket (FP < 3-4%).
- **"Peça prova de exploração, não um número CVSS"** — mostra exatamente como explorou.
- **Remediação específica do framework** (fix no stack do dev), até **PR pronto pra merge**.
- Geração de OpenAPI a partir do código; auth multi-usuário em linguagem natural.

---

## 2. Onde a Yubel já está (e o gap)

O modelo `Finding` da Yubel **já tem os campos certos**: `location`, `evidence`,
`remediation`, `cwe/cve`, `owasp/owasp_api/mitre`, `risk_score`, `confidence`,
`corroboration`, `rationale`. O problema **não era o schema — era o
preenchimento**. Desde a 0.7.0 o `remediation` sai preenchido em **todo**
finding (KB determinística por CWE → categoria OWASP → genérico seguro), e o
bloco de prova (param/payload/request/response) sai preenchido no **nuclei** e
no **dalfox**. O que ainda falta é prova nos outros engines — zap, wapiti,
nikto, schemathesis, testssl.

---

## 3. Plano priorizado (foco: onde + como corrigir)

### P1 — Prova por finding (request/response + localização exata)  ⭐ maior valor
**Parcialmente entregue na 0.7.0**: nuclei (roda com `-irr`) e dalfox já
preenchem `param`/`payload`/`request`/`response`, e o HTML renderiza o bloco de
prova. Falta estender aos demais engines — zap, wapiti, nikto, schemathesis.

Adaptação **determinística** do proof-based da Invicti (sem exploit destrutivo):
- Capturar e guardar, por finding, o **par request/response** que disparou a
  detecção — o nuclei já dá `matched-at`, `matcher-name`, `extracted-results`;
  o dalfox dá `evidence`/`poc`/`payload`; o nikto dá a linha crua. Normalizar
  isso num bloco de evidência.
- **Localização exata**: URL + **parâmetro** + **payload injetado** + onde
  refletiu. É literalmente o "onde está o erro".
- No HTML: bloco de evidência **copiável/colapsável** (request destacado,
  trecho da resposta que prova, curl de reprodução).

### ~~P2 — Base de conhecimento de remediação~~ — **entregue na 0.7.0**
`analysis/remediation.py`: KB determinística indexada por CWE → categoria OWASP
→ genérico seguro, aplicada a todo finding em `analyze()`. Remediação vinda do
próprio engine sempre ganha. Sem rede, sem modelo.

### ~~P3 — Tier "Confirmado vs Precisa revisão"~~ — **entregue na 0.7.0**
`analysis/__init__._verified`: corroborado por 2+ engines, sintetizado como
chain, payload com prova observável, ou observação direta de transporte =
**Confirmed**; o resto, **Needs review**. HTML e Markdown mostram o badge;
o SARIF expõe `verified`.

### P4 — Re-teste de correção (`--retest`)
- Reaproveita o baseline diff que já existe (new/existing/regressed/fixed):
  um `--retest baseline.json` re-roda **só as URLs/params dos findings antigos**
  pra confirmar o que foi corrigido. "Fixed issues stay fixed", barato.

### P5 — Mapeamento de compliance
- Além de OWASP/CWE/MITRE, lookup determinístico → **PCI-DSS, SOC2, ISO 27001,
  OWASP ASVS**. Seção "impacto de compliance" no relatório (jogada do Checkmarx).

### P6 — Correlação com SAST (inventário unificado, à la Checkmarx)
- Yubel ingere **SARIF externo** (SAST/outros) e correla com os findings DAST:
  DAST-confirmado + sink apontado por SAST = cadeia de altíssima confiança.
  Reforça o "cérebro de correlação" que já é o diferencial.

### P7 — Alinhar com o OWASP ASTF (cobertura de API)
- Adotar do ASTF: **multi-identidade** (BOLA/IDOR trocando token), **mTLS**,
  **ReDoS**, **GraphQL DoS (depth/alias/batch)** como novas regras/engines.
- Publicar uma **matriz de rastreabilidade** (o que a Yubel pega/erra contra
  crAPI, VAmPI, Juice Shop) — transparência que gera confiança.

---

## 4. A camada OpenAI/LLM — sem trair o air-gapped

A tensão é real: o mercado usa LLM pra remediação/validação, mas o **diferencial
da Yubel é ser determinística e air-gapped**. A solução não é escolher um lado —
é **separar as camadas**:

> **O núcleo (detecção + prova) continua 100% determinístico e offline. A IA é
> uma camada OPCIONAL de *enriquecimento*, nunca o árbitro da vulnerabilidade.**

Desenho proposto (`yubel explain` / flag `--ai`):
- **Entra:** os findings já detectados + a evidência determinística (request/response).
- **A IA faz só isto:** (a) explicação em linguagem clara, (b) **fix específico
  do framework** do dev, (c) rascunho de **patch/PR**. Ela **não decide** se algo
  é vulnerável — isso continua sendo a prova determinística.
- **Providers plugáveis:** OpenAI API **ou** modelo local (Ollama/llama.cpp) pra
  quem quer o benefício sem egress.
- **Trava dura:** em `--offline`/air-gapped a camada de IA é **proibida** e o
  scan roda igual. O relatório marca claramente o que é **prova determinística**
  vs **texto sugerido por IA** (auditabilidade preservada).

Isso te dá o "algo da OpenAI" que você buscou — remediação e narrativa que os
enterprise amam — **mantendo** a bandeira "sem LLM no núcleo, reproduzível,
air-gapped". É o melhor dos dois mundos, e vira até argumento de marketing:
*"IA quando você quer, determinismo quando você precisa."*

---

## 5. Ordem sugerida de implementação

1. **P1 + P2 + P3** juntos → é o coração do que você pediu ("onde + como
   corrigir" + prova). Entrega o maior salto de qualidade percebida no relatório.
2. **P4** (re-teste) — barato, reaproveita baseline.
3. **Camada IA opcional (seção 4)** — diferencia de novo e responde a OpenAI.
4. **P5/P6/P7** — evolução de médio prazo (compliance, SAST, API).

Fontes: Invicti (proof-based scanning, redução de FP), Checkmarx DAST/One,
OWASP API Security Testing Framework, e comparativos de DAST com IA (Escape,
Bright, Burp AI, StackHawk).
