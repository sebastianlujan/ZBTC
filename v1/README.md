# ZBTC

A minimal, from-scratch implementation of the internal transfer layer of the
*Shielded Bitcoin* paper on Bitcoin Core regtest. It has private notes, nullifiers, a
Groth16 proof (Circom + snarkjs) per transfer, one `OP_RETURN` envelope per transfer, and
deterministic client-side replay.

> **Units are SIMULATED. This is not private BTC.** There is no peg and no redemption.
> Bitcoin orders and stores the envelopes, and every rule is enforced by the clients that
> replay the chain. The trusted setup is a single dev contribution, so whoever ran
> `pnpm circuit` can forge proofs. Do not use any of this with real value.

Research notes, limits, citations and the full adversarial results are in
[`docs/research.md`](docs/research.md) (Spanish).

## Requirements

- Bitcoin Core 32.1 (`brew install bitcoin`)
- circom 2.2.3
- Node 24 and pnpm 10

## Quickstart

```sh
pnpm install
pnpm circuit        # compile circuits, fetch ppot_0080_15.ptau (38 MB), dev Groth16 setup
pnpm demo           # Alice -> Bob -> Carol on a fresh regtest node; expects 70/20/10 units
```

`pnpm demo` wipes and recreates `.regtest/` and `.zbtc/`. It starts `bitcoind` on RPC port
18543 (override with `RPCPORT=`) and stops it at the end unless `KEEP=1`. It finishes by
checking three things:
- the final balances are 70/20/10 units;
- two independent processes compute the same state digest;
- the `OP_RETURN` carries no amount or address in clear.

## Tests

```sh
pnpm typecheck
pnpm test:unit      # codec, crypto, tree, indexer (synthetic blocks), circuit C1–C12
pnpm test:e2e       # spawns its own bitcoind nodes: publish, double-spend, soundness, reorg, agreement, recovery
```

## CLI

`pnpm zbtc <command>`:

| Command | What it does |
|---|---|
| `init` | write `.zbtc/config.json`, create the miner wallet, mine 101 blocks |
| `wallet new <name>` | create a shielded seed and a funded `<name>-fee` bitcoind wallet |
| `address <name>` | print the shielded address (`zbtcrt…`) |
| `genesis <name>=<v> ...` | declare the genesis note inventory (`startHeight = tip + 1`) |
| `mine <n>` | mine n blocks |
| `send <from> <to> <amount>` | prove, publish and lock a 2-in/2-out transfer |
| `notes <name>` | list notes with their derived state (`candidate`, `confirmed(k)`, `spendable`, `pending-spend`, `spent`) |
| `balance <names...>` | balances in units |
| `index [--digest]` | replay from genesis; print the root, counts and the state digest |

## Layout

```
circuits/   transfer_template.circom (statement), merkle.circom, transfer.circom (main),
            variants/ (norange, nosquare: test-only unsafe builds)
src/        constants, crypto, tree, codec, prover, rpc, indexer (replay), wallet, cli
scripts/    circuit.sh (build + dev setup), demo.sh
test/       unit/, circuit/, e2e/, helpers/
docs/       claude_plan.md, research.md, architecture.excalidraw,
            architecture-layers.excalidraw
```

## Protocol in one screen

- **Note:** `(v, owner, rseed)` with commitment `cm = Poseidon(3, v, owner, rseed)`.
  `owner = Poseidon(1, sk_spend)`.
- **Nullifier:** `nf = Poseidon(4, sk_nf, rseed, pos)`, where `sk_nf = Poseidon(2, sk_spend)`
  is derived inside the circuit.
- **Public inputs:** `[root, h_body, nf0, nf1, cm0, cm1]`. Values are range-checked to
  64 bits, and positions to 20 bits.
- **Envelope:** 572 bytes in one `OP_RETURN` (`magic | version | type | h_anchor | nf | cm |
  epk | ct | proof`). The note plaintext is encrypted off-circuit with X25519 + HKDF +
  ChaCha20-Poly1305.
- **Replay** runs in block order, then tx order. Per envelope it checks:
  1. extraction
  2. canonical parse, including the G2 subgroup check
  3. `h_body`
  4. anchor window
  5. nullifier uniqueness
  6. Groth16 verify

  Only then does it apply the mutation, atomically. The first nullifier wins; duplicates are
  detected by nullifier, never by txid or proof bytes.

## Deviations from the paper

See `docs/research.md` §10. The most important one: the paper proves note encryption inside
the circuit, and ZBTC does not. A sender can therefore publish an undecryptable note; it is
accepted, and the recipient loses it.
