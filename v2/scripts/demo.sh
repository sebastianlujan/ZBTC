#!/usr/bin/env bash
# ZBTC v2 demo on Bitcoin regtest: a toy note's witness decrypts AADP
# matrices, the recovered mu unwraps a Bitcoin key, and that key signs a
# Taproot key-path spend of one native regtest UTXO.
#
# This is NOT private BTC (see README.md). .regtest/ and .demo/ belong ONLY to
# this demo: they are wiped on every run. Set KEEP=1 to leave the node running.
# RPCPORT defaults to 18643, away from Core's 18443 and v1's 18543.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DATADIR="$ROOT/.regtest"
RPCPORT="${RPCPORT:-18643}"
BCLI=(bitcoin-cli -regtest -datadir="$DATADIR" -rpcport="$RPCPORT")
step() { printf '\n== %s\n' "$*"; }

stop_node() {
  [[ -f "$DATADIR/regtest/bitcoind.pid" ]] || return 0
  local pid
  pid="$(<"$DATADIR/regtest/bitcoind.pid")"
  "${BCLI[@]}" stop >/dev/null 2>&1 || true
  for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
}

step "reset .regtest/ and .demo/"
stop_node
rm -rf "$DATADIR" "$ROOT/.demo"
mkdir -p "$DATADIR"

step "start bitcoind (regtest)"
bitcoind -regtest -datadir="$DATADIR" -daemon -server=1 -txindex=1 -fallbackfee=0.0002 \
  -acceptnonstdtxn=0 -listen=0 -rpcport="$RPCPORT" >/dev/null
"${BCLI[@]}" -rpcwait -rpcwaittimeout=60 getblockcount >/dev/null
bitcoind -version | head -1

cleanup() {
  if [[ "${KEEP:-0}" == "1" ]]; then
    echo "KEEP=1: node left running (${BCLI[*]})"
    return
  fi
  stop_node
}
trap cleanup EXIT

step "note -> AADP -> key -> Taproot spend"
DATADIR="$DATADIR" RPCPORT="$RPCPORT" pnpm exec tsx src/main.ts
