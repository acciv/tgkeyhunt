#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

(cd go && go run ./cmd/tgkeyscan \
  --dir ../examples/fixtures \
  --out ../examples/findings.json)

(cd python && PYTHONPATH=. python3 -m tgkeyhunt.report \
  ../examples/findings.json ../examples/report.md)

echo "--- report.md ---"
cat examples/report.md
