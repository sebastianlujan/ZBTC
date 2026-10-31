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

## UI

```sh
pnpm ui             # http://127.0.0.1:8543
```

A local demo wallet for live demos (page copy in Spanish). The main view is a wallet app,
shown inside an iPhone frame on wide screens and full screen on phones, with two accounts,
Alice and Bob: a shielded ZBTC balance, a Bitcoin fee wallet, send (private or public),
receive, and the activity list. Every action runs the real CLI (`zbtc`, `bitcoin-cli`,
`bitcoind`). A side panel has three terminal-styled tabs:

- `terminal`: every command, streamed as it runs, with a comment that says why it runs.
- `explorer`: what anyone sees on the chain: recent blocks, the mempool, and each transaction
  with a Sankey diagram and its block. A ZBTC transfer can be decrypted with Alice's or Bob's
  key, the way a viewing key would.
- `debug`: node and replay state, each wallet's notes, and the decoded `OP_RETURN` envelope:
  byte map, fields, leak checks and the raw transaction JSON.

ZBTC values are simulated units, not BTC. The diagrams use Apache ECharts 5.6.0 and the phone
frame uses devices.css 0.2.0, both from jsDelivr (pinned, with subresource integrity hashes),
so they need network access; without it the wallet still works, unframed and without
diagrams. Reset (in `debug`) wipes `.regtest/` and `.zbtc/`, like `pnpm demo`, and uses RPC
port 18543. If another node already uses that port, set `RPCPORT=`. Set `PORT=` to change the
HTTP port.

## Layout

```
circuits/   transfer_template.circom (statement), merkle.circom, transfer.circom (main),
            variants/ (norange, nosquare: test-only unsafe builds)
src/        constants, crypto, tree, codec, prover, rpc, indexer (replay), wallet, cli
scripts/    circuit.sh (build + dev setup), demo.sh
ui/         server.ts (runs the CLI per action, streams it), index.html, app.js, app.css
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
