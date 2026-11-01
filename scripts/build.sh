#!/usr/bin/env bash
# Build the browser scripts (esbuild) and a static linux/amd64 binary.
set -euo pipefail
cd "$(dirname "$0")/.."
export TMPDIR=${TMPDIR:-/var/tmp} GOMAXPROCS=${GOMAXPROCS:-2}
(cd client && { [ -d node_modules ] || npm install --no-audit --no-fund; } && npx tsc --noEmit -p . && node build.mjs)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/dsh-seal ./cmd/dsh-seal
go build -o bin/mockupstream ./cmd/mockupstream
go build -o bin/sealbench ./cmd/sealbench
go build -o bin/fakeedge ./test/fakeedge
ls -la bin/
