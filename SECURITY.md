# Security Policy

## Authorized use only

Yubel performs **active** dynamic testing — it sends real attack traffic and,
with intrusive engines enabled, can modify data or exploit weaknesses. Use it
**only** against systems you own or have explicit, written authorization to test.
Unauthorized scanning may be illegal in your jurisdiction. You are solely
responsible for your use of this tool.

Safe defaults:
- Intrusive engines (e.g. `sqlmap`) are **off** unless you pass
  `--include-intrusive` or name them explicitly.
- `kube-hunter` runs in passive mode; active exploitation requires
  `options.kube-hunter.active: true`.
- Point scans at **staging** first.
- ZAP runs its **passive** baseline scan by default. `options.zap.mode: full`
  switches to `zap-full-scan.py`, which actively attacks the target — set it
  deliberately, and only where you are authorised to.
- **Internal addresses are refused by default.** Link-local (169.254.0.0/16 —
  the cloud instance metadata service), loopback and RFC1918 targets are
  rejected before anything runs, and URLs the crawler discovers at runtime are
  filtered the same way. The reason is specific: that endpoint answers with the
  credentials of whatever is running the scan, nuclei runs with `-irr` so the
  response is attached to the finding, and `redact.py` deliberately does not
  mask a secret found *on a target* — masking it would destroy the finding.
  Pass `--allow-internal` (or `allow_internal: true`) for an authorized
  internal assessment. Note the limit: **a hostname is never resolved**, so a
  name pointing at an internal address still passes. This refuses what can be
  refused by inspection, not everything internal that is reachable.
- **`scope` and `exclude` are not implemented.** They are accepted in a
  target and read by no engine, so a config that sets them is not scoped in
  any way. Do not rely on them to bound a scan; bound it by pointing Yubel
  only at hosts you are authorised to test. Tracked in
  [#18](https://github.com/ggeorgeazevedo/yubel/issues/18).

## Reporting a vulnerability in Yubel

If you find a security issue **in Yubel itself** (not in a target you scanned):

- Do **not** open a public GitHub issue.
- Email the maintainers (see repository metadata) or use GitHub Private
  Vulnerability Reporting on this repo.
- Include a description, reproduction steps, and impact. We aim to acknowledge
  within 5 business days.

## Handling of scan output

Reports can contain sensitive data (tokens in URLs, evidence snippets, internal
hostnames). Treat `yubel.json`/`.html`/`.sarif` as confidential: store them in
access-controlled locations and prefer `${ENV}` expansion so secrets never live
in `yubel.yaml`.
