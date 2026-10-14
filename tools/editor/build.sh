#!/usr/bin/env bash
# Builds internal/web/static/editor.js (the embedded CodeMirror 6 policy editor) from src/ with the
# exact versions in package.json / package-lock.json. node_modules lives in a temporary directory, so
# the repository holds only the sources, the lock file and the built file. Run from anywhere:
#   tools/editor/build.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/../../internal/web/static/editor.js"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp "$here/package.json" "$tmp/"
[ -f "$here/package-lock.json" ] && cp "$here/package-lock.json" "$tmp/"
cp -R "$here/src" "$tmp/src"
cd "$tmp"
if [ -f package-lock.json ]; then npm ci --no-audit --no-fund --silent; else npm install --no-audit --no-fund --silent; cp package-lock.json "$here/"; fi
npx esbuild src/policy-editor.js --bundle --minify --format=iife --target=es2020 \
  --legal-comments=eof --outfile="$out"
echo "built $out ($(wc -c <"$out") bytes)"
