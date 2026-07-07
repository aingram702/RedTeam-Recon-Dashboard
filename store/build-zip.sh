#!/usr/bin/env bash
# Build the uploadable Chrome Web Store package: only the extension runtime
# files (manifest + src + icons). Dev tooling and store assets are excluded.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(python3 -c "import json;print(json.load(open('manifest.json'))['version'])")"
OUT="dist/recon-dashboard-v${VERSION}.zip"

mkdir -p dist
rm -f "$OUT"

zip -r -X "$OUT" manifest.json src icons \
  -x '*.DS_Store' -x '*/.*' >/dev/null

echo "Built $OUT"
unzip -l "$OUT"
