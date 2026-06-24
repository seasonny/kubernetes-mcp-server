#!/usr/bin/env bash
# Build and publish rh-tam-kubernetes-mcp-server to npm. Never prints tokens.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <semver-version>" >&2
  echo "Example: $0 0.1.15" >&2
  exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "ERROR: version must be semver (e.g. 0.1.15), got: $VERSION" >&2
  exit 1
fi

echo "=== release $VERSION ==="
echo

# Preflight
"$ROOT/scripts/release-check.sh"
echo

# Auth: clean stale .npmrc that break npm login
echo "[clean] removing npm/**/.npmrc (safe; tokens not printed)"
find npm -name '.npmrc' -delete 2>/dev/null || true

if [[ -z "${NPM_TOKEN:-}" ]]; then
  if ! npm whoami >/dev/null 2>&1; then
    echo "ERROR: npm not authenticated. Run: npm login" >&2
    echo "   or: export NPM_TOKEN=<token-from-npmjs.com>" >&2
    exit 1
  fi
  echo "[auth] using npm login ($(npm whoami))"
else
  echo "[auth] using NPM_TOKEN env (value not shown)"
fi
echo

# Confirm
read -r -p "Publish rh-tam-kubernetes-mcp-server@${VERSION} to npm? [y/N] " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi
echo

# Build all platforms + copy binaries
echo "[build] make npm-copy-binaries ..."
make npm-copy-binaries
echo

# Publish (Makefile sets jq version from NPM_VERSION)
echo "[publish] make npm-publish ..."
NPM_VERSION="$VERSION" make npm-publish
echo

# Cleanup local .npmrc so tokens are not left on disk
find npm -name '.npmrc' -delete 2>/dev/null || true

# Verify
echo "[verify]"
PUBLISHED=$(npm view "rh-tam-kubernetes-mcp-server@${VERSION}" version 2>/dev/null || true)
if [[ "$PUBLISHED" == "$VERSION" ]]; then
  echo "  OK  npm: rh-tam-kubernetes-mcp-server@${VERSION}"
else
  echo "  WARN  expected ${VERSION}, got: ${PUBLISHED:-<not found>}"
  exit 1
fi

echo
echo "Done. Optional:"
echo "  git tag v${VERSION} && git push origin v${VERSION}"
echo "  npx -y rh-tam-kubernetes-mcp-server@${VERSION} --version"
