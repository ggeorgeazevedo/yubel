# Why I built Yubel: a DAST orchestrator that correlates findings instead of just stacking them

> Draft article (dev.to / Medium / Hacker News / LinkedIn Articles). Tweak the **[personal]** notes to add your own story — a technical post with a concrete pain point engages far more.

---

## The problem nobody solves for you

If you've ever run a dynamic application security scanner (DAST) in a real environment, you know the scene: you point ZAP, Nuclei, Nikto and testssl.sh at a target, and you get back **four separate reports, each speaking its own language.**

Then comes the work the tools *don't* do for you:

- ZAP found an "external redirect". Nuclei found an "open redirect". **Are those the same thing?**
- testssl reported weak TLS. Nuclei found a login endpoint with no rate limit. **Together, do those chain into a real attack path?**
- You scanned 8 microservices and the same security header is missing on 6 of them. **Is that one problem or six?**

Nobody hands you that correlated view. You open the reports side by side, cross-reference them by hand, and hope you don't miss the combination that matters. **[personal: drop in a time this bit you — a "low" finding that, combined with another, was actually critical, or hours lost cross-referencing reports.]**

That pain is why I built **Yubel**.

## What Yubel is *not*

First things first: Yubel **doesn't reinvent any scanner.** That's deliberate.

The open-source DAST engines are already excellent, with years of community work behind them — ZAP, Nuclei, Nikto, Wapiti, testssl.sh, dalfox, sqlmap, schemathesis, kube-hunter. Rewriting that would be both arrogant and wasteful.

Yubel is the **conductor, not another instrument.** It orchestrates those engines against web apps, REST/GraphQL APIs, cloud, containers and Kubernetes, normalizes everyone's output into a single model — and then does the part no single scanner does.

## The "correlation brain"

Because Yubel sees **every engine's output for a target at once**, it adds an analysis layer that a single scanner structurally cannot:

**1. Cross-engine consensus.** A finding reported by 2+ engines is flagged *corroborated* and confidence-upgraded. It's using the engines as a jury — **deterministically**, with no probabilistic validator. Duplicates merge, keeping the worst severity and crediting every reporter.

**2. Attack-chain synthesis.** Yubel recognizes when separate findings combine into a real exploitation path and promotes it to its own high-impact finding. 13 rules today, for example:

- *SSRF + cloud host → IMDS credential theft*
- *XSS + non-HttpOnly cookie → account takeover*
- *anonymous K8s API + exposed kubelet → cluster takeover*
- *JWT alg=none + admin → auth bypass*

No isolated scanner reports these chains — because none of them sees both ends.

**3. Systemic correlation across targets.** When the same weakness class shows up on 2+ targets, Yubel raises a single *systemic* finding: "fix centrally, resolve everywhere." A tool that sees one app at a time can't do that.

**4. Deterministic evidence trail.** Every finding carries a reproducible "why we believe this" — which engines, corroboration, taxonomy (OWASP/CWE/MITRE), risk score. Auditable reasoning instead of a model's guess.

## The design bet: no LLM, no cloud

Here's the decision that sets Yubel apart from the pack.

The whole industry is running in the same direction: **bolt an LLM on to "validate" findings.** Send the finding to the model, it says "real" or "false positive."

Yubel goes **the opposite way.** And it's a choice, not a limitation.

- **No LLM, no cloud.** The core makes **zero outbound calls** — it only ever talks to the targets you point it at. Your results never leave your perimeter.
- **An `--offline` switch on top of that.** Every engine either honours it with a switch verified against that tool's own documentation — nuclei's `-ni -duc`, ZAP's `-silent`, nikto's `-nolookup`, testssl's `--nodns none`, wapiti's `--no-bugreport` — or is skipped, with the reason written into the report. Two are skipped today, and the report says which and why. The alternative was to run them and call the scan offline anyway, which is how the word stops meaning anything. The core itself runs entirely inside isolated, air-gapped, on-prem networks — where AI-driven tools simply can't go.
- **Deterministic and reproducible.** The same scan yields the same result, every time.

Why does that matter? **Because audit.** If your security result depends on a model that might answer differently tomorrow, you don't have an auditable result — you have an opinion. In a regulated environment, that doesn't fly. **[personal: if you've worked in regulated/financial/gov/health environments, say why reproducibility isn't negotiable there.]**

It's not that LLMs have no value. It's that for the *core* of a security tool that has to be trustworthy and auditable, **determinism beats probability.** (And if you *do* want an AI scanner, Yubel orchestrates it as just one more engine — its own brain stays deterministic.)

## How to use it

Three ways, all open-source (Apache-2.0):

```bash
# installed
pip install yubel
yubel scan -t https://staging.example.com --fail-on high

# Docker (batteries-included image with every engine bundled)
docker run --rm -v "$PWD/out:/out" \
  ghcr.io/ggeorgeazevedo/yubel:latest \
  scan -t https://staging.example.com -o /out

# in CI, as a GitHub Action
# - uses: ggeorgeazevedo/yubel@v0
#   with:
#     target: https://staging.example.com
#     fail-on: high
```

Output comes as HTML (an editorial report), SARIF (drops straight into GitHub code scanning), Markdown and JSON — with a 0–100 risk score, an A–F per-target grade and an OWASP coverage matrix.

Air-gapped? Just add `--offline`.

## What's next

Yubel is live and shipped across three channels (PyPI, GHCR and the GitHub Marketplace), with full CI/CD. But the interesting part is what it can grow into: **more attack-chain rules, more orchestrated engines, richer taxonomy.**

If you work in AppSec/DevSecOps, I'd love your feedback — especially on the correlation rules and the taxonomy mapping. And a ⭐ genuinely helps the project reach more people.

👉 **github.com/ggeorgeazevedo/yubel**

**[personal: close with your own "why" — what you want Yubel to be for the community, or an invitation to contribute.]**

---

*Yubel is open-source under Apache-2.0. It orchestrates third-party OSS engines; only run it against systems you're authorized to test.*
