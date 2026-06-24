#!/usr/bin/env bash
# Preflight checks for kubernetes-mcp-server release. No publish, no secrets printed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
WARN=0

ok()   { echo "  PASS  $*"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }
warn() { echo "  WARN  $*"; WARN=$((WARN + 1)); }

echo "=== kubernetes-mcp-server release-check ==="
echo

# --- Secret leak: staged / tracked files ---
echo "[secrets]"
if git diff --cached -G '_authToken|npm_[a-zA-Z0-9]{10,}' --name-only 2>/dev/null | grep -q .; then
  bad "staged diff may contain npm tokens (review: git diff --cached)"
else
  ok "no token patterns in staged diff"
fi

TRACKED_NPMRC=$(git ls-files 'npm/**/.npmrc' '.npmrc' 2>/dev/null || true)
if [[ -n "$TRACKED_NPMRC" ]]; then
  bad "tracked .npmrc files (must be gitignored): $TRACKED_NPMRC"
else
  ok "no tracked .npmrc"
fi

TRACKED_BINS=$(git ls-files 'npm/**/bin/*' 'dist/*' 2>/dev/null | grep -vE '/index\.js$' || true)
if [[ -n "$TRACKED_BINS" ]]; then
  bad "tracked binaries in npm/**/bin or dist/ (must be gitignored)"
else
  ok "no tracked build binaries"
fi

LOCAL_NPMRC=$(find npm -name '.npmrc' 2>/dev/null || true)
if [[ -n "$LOCAL_NPMRC" ]]; then
  warn "local npm/**/.npmrc exists (delete before publish if using npm login): run find npm -name .npmrc -delete"
else
  ok "no local npm/**/.npmrc"
fi
echo

# --- Tooling ---
echo "[tooling]"
for cmd in go npm jq git; do
  if command -v "$cmd" >/dev/null 2>&1; then ok "$cmd available"; else bad "$cmd missing"; fi
done
echo

# --- npm auth (metadata only) ---
echo "[npm auth]"
if [[ -n "${NPM_TOKEN:-}" ]]; then
  ok "NPM_TOKEN is set (CI mode)"
elif npm whoami >/dev/null 2>&1; then
  ok "npm whoami: $(npm whoami)"
else
  bad "not logged in (npm login) and NPM_TOKEN unset"
fi

if npm view rh-tam-kubernetes-mcp-server version >/dev/null 2>&1; then
  ok "npm registry latest: $(npm view rh-tam-kubernetes-mcp-server version)"
else
  warn "cannot read rh-tam-kubernetes-mcp-server from registry (network or package name)"
fi
echo

# --- Git state ---
echo "[git]"
if [[ -z "$(git status --porcelain 2>/dev/null)" ]]; then
  ok "working tree clean"
else
  warn "uncommitted changes present (commit before release)"
  git status -sb
fi
echo

# --- Tests (portal-focused, fast) ---
echo "[tests]"
if go test -count=1 ./pkg/mcp/ -run 'RedHat|CreateCase|ReadCase|AddCase|Upload' >/dev/null 2>&1; then
  ok "portal unit tests"
else
  bad "portal unit tests failed (run: go test -v ./pkg/mcp/ -run 'RedHat|ReadCase|AddCase')"
fi
echo

echo "=== summary: $PASS passed, $WARN warnings, $FAIL failed ==="
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
