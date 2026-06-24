# Release reference

## Full checklist

```
- [ ] ./scripts/release-check.sh — all PASS
- [ ] Version chosen (semver, > npm latest)
- [ ] go test ./pkg/mcp/ ... PASS
- [ ] git commit (no .npmrc, no dist/, no npm/**/bin/)
- [ ] git push origin main
- [ ] ./scripts/release.sh <VERSION>
- [ ] git tag v<VERSION> && git push origin v<VERSION>
- [ ] npm view rh-tam-kubernetes-mcp-server@<VERSION>
```

## GitHub push

```bash
git status
git add .gitignore Makefile pkg/ npm/ scripts/ .cursor/
git commit -m "$(cat <<'EOF'
feat(redhat-portal): <short summary>

EOF
)"
git push origin main
git tag v0.1.15
git push origin v0.1.15
```

## npm publish (manual)

```bash
# Clean auth debris from failed runs
find npm -name '.npmrc' -delete

# Option A: logged in locally
npm whoami
NPM_VERSION=0.1.15 make npm-copy-binaries
NPM_VERSION=0.1.15 make npm-publish

# Option B: CI token (do not echo token)
export NPM_TOKEN='...'   # from https://www.npmjs.com/settings/~youruser/tokens
NPM_VERSION=0.1.15 make npm-publish
```

## ENEEDAUTH troubleshooting

Symptom: `npm whoami` works, `make npm-publish` fails.

Cause: `npm/<pkg>/.npmrc` contains `//registry.npmjs.org/:_authToken=` (empty).

Fix:

```bash
find npm -name '.npmrc' -delete
npm whoami
NPM_VERSION=x.y.z make npm-publish
```

## Files that must NOT enter git

| Path | Reason |
|------|--------|
| `npm/**/.npmrc` | npm auth token |
| `npm/**/bin/*` | compiled binaries (rebuilt at publish) |
| `dist/` | local build artifacts |
| `tmp.json` | jq temp from Makefile |
| `~/.npmrc` | user credentials |

## Partial publish recovery

If some platform packages published but others failed:

```bash
npm view rh-tam-kubernetes-mcp-server-darwin-arm64 versions --json
# Re-run only failed platforms or full make npm-publish (npm rejects duplicate version)
```

## Case Agent integration note

After npm release, point Case Agent config to:

```json
"mcpServers": {
  "kubernetes": {
    "command": "npx",
    "args": ["-y", "rh-tam-kubernetes-mcp-server@<VERSION>"]
  }
}
```

JSON contract: `read_case_comments_rh_portal` returns `source: hydra:getCaseComments`, not legacy `[1] Author...` text.
