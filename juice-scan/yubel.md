# Yubel — Security Assessment

*2026-07-29 21:39 -03 · Yubel v0.6.0 · 90.32s*

## Executive summary

- **Risk grade:** A  (score 10.0/100)
- **Findings:** 1 — 0 critical, 0 high, 0 medium, 0 low, 1 info

## OWASP Top 10 coverage

| Category | Findings |
|---|---|

## Findings

### 1. Live service: 200 OWASP Juice Shop — Info (risk 10) · _new_

- **Engine:** `httpx` · confidence high
- **Location:** `http://localhost:3000`

Server=; Tech=

- **Why we believe this:** Reported by httpx. Confidence high; composite risk 10/100.
---

## Engine coverage

| Engine | Target | Status | Findings | Time |
|---|---|---|---|---|
| `dalfox` | http://localhost:3000 | ok | 0 | 0.39s |
| `httpx` | http://localhost:3000 | ok | 1 | 2.34s |
| `katana` | http://localhost:3000 | ok | 0 | 21.93s |
| `nikto` | http://localhost:3000 | ok | 0 | 54.25s |
| `nuclei` | http://localhost:3000 | ok | 0 | 68.38s |
| `testssl` | http://localhost:3000 | ok | 0 | 54.83s |
| `wapiti` | http://localhost:3000 | skipped | 0 | 0.0s |
| `zap` | http://localhost:3000 | skipped | 0 | 0.0s |
