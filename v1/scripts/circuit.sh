#!/usr/bin/env bash
# Builds the ZBTC circuits and a Groth16 setup for each of them.
#
# !!! DEV ONLY, INSECURE !!!
# Phase 2 is a SINGLE contribution made on this machine with fixed dev entropy
# (snarkjs also mixes in OS randomness). Whoever ran this script controlled the
# only contribution and can forge proofs, i.e. mint arbitrary notes. These keys
# are for local tests and the regtest demo only. A real deployment needs a
# multi-party phase-2 ceremony.
#
# Phase 1 is the public PSE perpetual powers of tau (ppot_0080_15, 2^15 powers).
#
# Idempotent: a step is skipped when its output exists and is newer than its
# inputs. Set FORCE=1 to rebuild everything.
#
# Outputs per circuit <name> (transfer, norange, nosquare):
#   build/<name>/<name>.r1cs, <name>.sym, <name>_js/<name>.wasm
#   build/<name>/<name>.zkey          final (dev) proving key
#   build/<name>/vkey.json            verification key
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FORCE="${FORCE:-0}"
BUILD="build"
PTAU_URL="https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_15.ptau"
PTAU="$BUILD/ppot_0080_15.ptau"
PTAU_SIZE=37842066
# Fixed so the contribution never prompts. Public, therefore worthless as a secret.
DEV_ENTROPY="zbtc dev-only insecure phase-2 entropy v1"
CIRCUITS=(
  "circuits/transfer.circom"
  "circuits/variants/norange.circom"
  "circuits/variants/nosquare.circom"
)

snarkjs() { pnpm exec snarkjs "$@"; }

# needs <output> <input>...: true when <output> must be (re)built.
needs() {
  local out="$1"; shift
  [[ "$FORCE" == "1" ]] && return 0
  [[ -s "$out" ]] || return 0
  local in
  for in in "$@"; do
    [[ "$in" -nt "$out" ]] && return 0
  done
  return 1
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# 1. Our circuits must never use unconstrained assignment. Fail closed: rg exit
#    1 means "no match"; anything else (match, missing rg, I/O error) aborts.
rg_status=0
rg -n -- '<--' circuits/ || rg_status=$?
if [[ "$rg_status" -eq 0 ]]; then
  echo "error: '<--' (unconstrained assignment) found in circuits/" >&2
  exit 1
elif [[ "$rg_status" -ne 1 ]]; then
  echo "error: the '<--' check could not run (rg exit $rg_status; is ripgrep installed?)" >&2
  exit 1
fi

mkdir -p "$BUILD"

# 2. Phase-1 powers of tau.
if [[ "$FORCE" == "1" || ! -s "$PTAU" ]]; then
  echo "==> downloading $PTAU_URL"
  curl -fL --retry 3 -o "$PTAU.part" "$PTAU_URL"
  mv "$PTAU.part" "$PTAU"
fi
actual_size=$(wc -c <"$PTAU" | tr -d ' ')
if [[ "$actual_size" != "$PTAU_SIZE" ]]; then
  echo "error: $PTAU is $actual_size bytes, expected $PTAU_SIZE" >&2
  exit 1
fi
ptau_sha=$(sha256_of "$PTAU")
echo "$ptau_sha  $(basename "$PTAU")" >"$BUILD/ptau.sha256"
echo "==> ptau ok: $actual_size bytes, sha256 $ptau_sha"

# 3. Compile + per-circuit dev setup.
CIRCOM_SOURCES=(circuits/*.circom circuits/variants/*.circom)
for src in "${CIRCUITS[@]}"; do
  name="$(basename "$src" .circom)"
  out="$BUILD/$name"
  r1cs="$out/$name.r1cs"
  zkey0="$out/${name}_0000.zkey"
  zkey="$out/$name.zkey"
  vkey="$out/vkey.json"
  mkdir -p "$out"

  if needs "$r1cs" "${CIRCOM_SOURCES[@]}"; then
    echo "==> [$name] compiling $src"
    circom "$src" --r1cs --wasm --sym --O2 --inspect -l node_modules -o "$out"
  else
    echo "==> [$name] r1cs up to date"
  fi

  if needs "$zkey0" "$r1cs" "$PTAU"; then
    echo "==> [$name] groth16 setup"
    snarkjs groth16 setup "$r1cs" "$PTAU" "$zkey0"
  fi

  if needs "$zkey" "$zkey0"; then
    echo "==> [$name] phase-2 contribution (DEV ONLY, INSECURE)"
    snarkjs zkey contribute "$zkey0" "$zkey" \
      --name="zbtc dev contribution (INSECURE)" -e="$DEV_ENTROPY / $name"
  fi

  if needs "$vkey" "$zkey"; then
    echo "==> [$name] exporting verification key"
    snarkjs zkey export verificationkey "$zkey" "$vkey"
  fi

  echo "==> [$name] r1cs info"
  snarkjs r1cs info "$r1cs"
done

echo "==> done. ptau sha256: $ptau_sha"
