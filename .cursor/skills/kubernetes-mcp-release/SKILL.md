---
name: kubernetes-mcp-release
description: >-
  Release rh-tam-kubernetes-mcp-server to GitHub and npmjs. Covers preflight
  checks, version bump, build-all-platforms, npm-publish auth pitfalls, and
  secret leak prevention. Use when the user asks to publish, release, push to
  npm, bump version, or run make npm-publish for kubernetes-mcp-server.
---

# kubernetes-mcp-server Release

## Quick path

From repo root:

```bash
# 1. Preflight only (safe, no publish)
./scripts/release-check.sh

# 2. Full release (prompts for version, runs tests + build + publish)
./scripts/release.sh 0.1.15
```

Read [reference.md](reference.md) for GitHub push, auth modes, and troubleshooting.

## Agent workflow

When the user wants to release:

1. Run `./scripts/release-check.sh` and fix any **FAIL** items.
2. Confirm target version (must be semver, e.g. `0.1.15`; bump patch from `npm view rh-tam-kubernetes-mcp-server version`).
3. Ensure changes are committed; offer commit message per repo style.
4. Run `./scripts/release.sh <VERSION>` **only after user confirms publish**.
5. After success: `git tag v<VERSION>`, `git push origin main --tags` if not done by script.
6. Verify: `npm view rh-tam-kubernetes-mcp-server@<VERSION> version`.

## Security rules (never skip)

- **Never** commit, log, or paste: `NPM_TOKEN`, `~/.npmrc`, `npm/**/.npmrc`, `RH_PORTAL_TOKEN`.
- `.npmrc` and `npm/**/bin/` are gitignored — do not force-add them.
- Before `git push`, run `git diff --cached` and reject if `_authToken` or `npm_` tokens appear.
- `make npm-publish` with empty `NPM_TOKEN` must **not** write local `.npmrc` (Makefile guard). If publish fails with `ENEEDAUTH`, run `find npm -name '.npmrc' -delete` then retry.
- Do not read or display contents of `~/.npmrc` or `npm/**/.npmrc`.

## Auth modes

| Mode | When | Command |
|------|------|---------|
| npm login | Local dev | `npm whoami` then `NPM_VERSION=x.y.z ./scripts/release.sh x.y.z` |
| NPM_TOKEN | CI / automation | `export NPM_TOKEN=...` (from npm Access Tokens, never commit) |

`npm whoami` uses `~/.npmrc`; `make npm-publish` runs in `npm/*/` subdirs. A **local empty** `.npmrc` overrides global login → `ENEEDAUTH`.

## Makefile targets

| Target | Purpose |
|--------|---------|
| `make build` | Local binary → `dist/rh-tam-kubernetes-mcp-server` |
| `make build-all-platforms` | All OS/arch → `dist/*` |
| `make npm-copy-binaries` | build-all-platforms + copy to `npm/**/bin/` |
| `NPM_VERSION=x.y.z make npm-publish` | Publish 6 platform pkgs + main pkg |

Always set `NPM_VERSION` explicitly. Do not rely on `git describe` alone (no tags → non-semver hash).

## Post-release verification

```bash
npm view rh-tam-kubernetes-mcp-server version
npx -y rh-tam-kubernetes-mcp-server@<VERSION> --version
# Case JSON contract: comments tool returns {"comments":[...],"source":"hydra:getCaseComments"}
```
