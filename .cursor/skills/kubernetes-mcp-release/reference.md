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

## npm/ 與 .gitignore

**不要**把整個 `npm/` 加進 `.gitignore`。

| 路徑 | 進 git？ | 原因 |
|------|----------|------|
| `npm/**/package.json` | ✅ 要 | 套件定義（名稱、版本、optionalDependencies） |
| `npm/**/bin/index.js` | ✅ 要 | npx 啟動器（原始碼） |
| `npm/**/bin/rh-tam-*` | ❌ 不要 | 編譯出的二進位（`make npm-copy-binaries` 產生） |
| `npm/**/.npmrc` | ❌ 不要 | npm token |

`.gitignore` 只影響**尚未被追蹤**的檔案。若 `package.json` 已在 git 裡，就算加了 `npm/` 到 gitignore，**仍會看到變更**——git 繼續追蹤已 index 的檔案。要停止追蹤需 `git rm --cached`（`package.json` 不建議這樣做）。

發布後 `package.json` 版本變更是正常的：`release.sh` 會用 `bump-npm-version.sh` 寫入新版本，應 commit 進 repo。

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
