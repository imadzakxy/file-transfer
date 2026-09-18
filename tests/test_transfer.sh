#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-./file-transfer}"
PORT="${PORT:-19090}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

head -c 1048576 /dev/urandom > "$TMP/input.bin"

"$BIN" receive "$PORT" "$TMP/out" --pass testpass >"$TMP/recv.log" 2>&1 &
PID=$!
sleep 0.5

"$BIN" send 127.0.0.1 "$PORT" "$TMP/input.bin" --pass testpass

wait "$PID"
cmp "$TMP/input.bin" "$TMP/out/input.bin"
echo "transfer test: OK"
