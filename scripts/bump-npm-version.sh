#!/usr/bin/env bash
# Sync version in all rh-tam npm package.json files (source files, safe to commit).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <semver-version>" >&2
  exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "ERROR: version must be semver, got: $VERSION" >&2
  exit 1
fi

MAIN="npm/rh-tam-kubernetes-mcp-server/package.json"
if [[ ! -f "$MAIN" ]]; then
  echo "ERROR: missing $MAIN" >&2
  exit 1
fi

jq --arg v "$VERSION" \
  '.version = $v | .optionalDependencies |= with_entries(.value = $v)' \
  "$MAIN" > tmp.json && mv tmp.json "$MAIN"

for pkg in npm/rh-tam-kubernetes-mcp-server-*/package.json; do
  [[ -f "$pkg" ]] || continue
  base=$(basename "$(dirname "$pkg")")
  bin_name="$base"
  suffix=""
  if [[ "$base" == *windows* ]]; then
    suffix=".exe"
  fi
  jq --arg v "$VERSION" --arg bin "$bin_name" --arg sfx "$suffix" \
    '.version = $v | .bin = {($bin): ("bin/" + $bin + $sfx)} | .files = ["bin/"]' \
    "$pkg" > tmp.json && mv tmp.json "$pkg"
done

rm -f tmp.json
echo "Bumped rh-tam-kubernetes-mcp-server npm packages to $VERSION"
