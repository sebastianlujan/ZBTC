#!/usr/bin/env bash
# ZBTC demo on Bitcoin regtest: Alice -> Bob -> Carol with shielded notes.
#
# Values are SIMULATED UNITS anchored and ordered by Bitcoin and validated by
# client-side replay (case B). This is NOT private native BTC.
#
# .regtest/ and .zbtc/ belong ONLY to this demo: they are wiped on every run.
# Set KEEP=1 to leave the node running at the end. RPCPORT defaults to 18543,
# not the regtest default 18443, because other local services (e.g. Docker
# containers running their own regtest node) commonly occupy 18443.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DATADIR="$ROOT/.regtest"
RPCPORT="${RPCPORT:-18543}"
BCLI=(bitcoin-cli -regtest -datadir="$DATADIR" -rpcport="$RPCPORT")
zbtc() { pnpm exec tsx src/cli.ts "$@"; }
step() { printf '\n== %s\n' "$*"; }

# ---- Fresh start ----
step "reset .regtest/ and .zbtc/"
if [[ -f "$DATADIR/regtest/bitcoind.pid" ]]; then
  pid="$(<"$DATADIR/regtest/bitcoind.pid")"
  "${BCLI[@]}" stop >/dev/null 2>&1 || true
  for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
fi
rm -rf "$DATADIR" "$ROOT/.zbtc"
mkdir -p "$DATADIR"

if [[ ! -f build/transfer/vkey.json ]]; then
  step "circuit build missing: pnpm circuit"
  pnpm circuit
fi

step "start bitcoind 32.1 (regtest, default datacarriersize)"
bitcoind -regtest -datadir="$DATADIR" -daemon -server=1 -txindex=1 -fallbackfee=0.0002 \
  -acceptnonstdtxn=0 -listen=0 -rpcport="$RPCPORT" >/dev/null
"${BCLI[@]}" -rpcwait -rpcwaittimeout=60 getblockcount >/dev/null
bitcoind -version | head -1

cleanup() {
  if [[ "${KEEP:-0}" == "1" ]]; then
    echo "KEEP=1: node left running (${BCLI[*]})"
    return
  fi
  local pid=""
  [[ -f "$DATADIR/regtest/bitcoind.pid" ]] && pid="$(<"$DATADIR/regtest/bitcoind.pid")"
  "${BCLI[@]}" stop >/dev/null 2>&1 || true
  if [[ -n "$pid" ]]; then
    for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
  fi
}
trap cleanup EXIT

# ---- Setup ----
step "zbtc init (miner wallet, 101 blocks)"
zbtc init --datadir .regtest --rpcport "$RPCPORT"

step "shielded wallets alice, bob, carol (+ <name>-fee bitcoind wallets for fees)"
for n in alice bob carol; do zbtc wallet new "$n"; done

step "genesis alice=100, then mine"
zbtc genesis alice=100
zbtc mine 1
zbtc balance alice bob carol

# ---- Transfers ----
step "alice -> bob 30"
OUT1="$(zbtc send alice bob 30)"
echo "$OUT1"
TX1="$(rg -o '^txid: ([0-9a-f]{64})' -r '$1' <<<"$OUT1")"

step "bob's notes before mining (expect candidate)"
zbtc notes bob
zbtc mine 1
step "bob's notes after mining (expect spendable)"
zbtc notes bob

step "bob -> carol 10"
zbtc send bob carol 10
zbtc mine 1

# ---- Results ----
step "balances (units)"
BAL="$(zbtc balance alice bob carol)"
echo "$BAL"
units() { rg -o "^$1: ([0-9]+) units" -r '$1' <<<"$BAL"; }
if [[ "$(units alice)/$(units bob)/$(units carol)" != "70/20/10" ]]; then
  echo "FAIL: expected 70/20/10 units, got $(units alice)/$(units bob)/$(units carol)" >&2
  exit 1
fi
echo "OK: 70/20/10 units"

step "index --digest (process 1)"
IDX1="$(zbtc index --digest)"
echo "$IDX1"
step "index --digest (process 2, fresh replay)"
IDX2="$(zbtc index --digest)"
echo "$IDX2"
D1="$(rg -o '^digest: ([0-9a-f]{64})' -r '$1' <<<"$IDX1")"
D2="$(rg -o '^digest: ([0-9a-f]{64})' -r '$1' <<<"$IDX2")"
if [[ -z "$D1" || "$D1" != "$D2" ]]; then
  echo "FAIL: digests differ: $D1 vs $D2" >&2
  exit 1
fi
echo "OK: identical digests $D1"

# ---- What Bitcoin sees ----
step "on-chain carrier of alice -> bob ($TX1)"
RAW="$("${BCLI[@]}" getrawtransaction "$TX1" 1)"
rg '"value"|"type"|"address"' <<<"$RAW" | sd '^\s+' '  '
SCRIPT="$(rg -o '"hex": "(6a4d3c02[0-9a-f]+)"' -r '$1' <<<"$RAW")"
echo "OP_RETURN script: $(( ${#SCRIPT} / 2 )) bytes: ${SCRIPT:0:72}..."
# No amount (30 or 70 as u64 LE) and no Bob address component appears in clear.
BOB_ADDR="$(zbtc address bob)"
BOB_OWNER="${BOB_ADDR:6:64}"
BOB_PKENC="${BOB_ADDR:70:64}"
for needle in 1e00000000000000 4600000000000000 "$BOB_OWNER" "$BOB_PKENC"; do
  if [[ "$SCRIPT" == *"$needle"* ]]; then
    echo "FAIL: found ${needle:0:16}... in clear in the OP_RETURN" >&2
    exit 1
  fi
done
echo "OK: the OP_RETURN holds only nf, cm, epk, ct and the proof; no amounts or addresses in clear"
echo "note: the fee input and change output above are a normal Bitcoin wallet and link publications"
