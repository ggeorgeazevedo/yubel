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
- Point scans at **staging** first. Scope with `scope`/`exclude` on each target.

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
