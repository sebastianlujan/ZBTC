# ZBTC v2

A functional demonstration on Bitcoin Core regtest. One toy note supplies the witness for
real AADP matrix decryption; the recovered secret derives an AEAD key that decrypts a
Bitcoin private key, and that key signs a Taproot key-path spend of one native regtest
UTXO. The fixture funds 101,000 sats, pays 100,000 sats to a fixed recipient and leaves a
1,000-sat fee. Algorithms 1–3 are reconstructed from the AADP paper.

> **This is not private BTC.** The note relation is deliberately insecure: a weak
> algebraic commitment with known secrets, not a secure hash. An honest setup operator
> knows every secret, including the Bitcoin key. The recipient receives the raw key, which
> can sign any spend, not only the demo transaction. Amounts, fees and the transaction
> graph stay visible on-chain, and one note gives no anonymity set. Do not use any of this
> with real value.

Status: **implemented**. Runtime validation: **passed** on Bitcoin Core 32.1 regtest.

- Plan: [`docs/codex_plan.md`](docs/codex_plan.md): relations, fixture, phases, checks
  and stop conditions.
- Implementation plan: [`docs/claude_plan.md`](docs/claude_plan.md): TypeScript
  milestones M0–M5 and the verification route.
- Research: [`docs/research.md`](docs/research.md): claims, limits, sources and
  measurements.

## Quickstart

```sh
pnpm install
pnpm demo
```

`pnpm demo` starts a fresh regtest node in `.regtest/` (RPC port 18643), runs the whole
path, prints the spend txid and eleven checks, and writes the artifacts to `.demo/`. It exits
non-zero if any check fails. `KEEP=1 pnpm demo` leaves the node running.

## Demo in one screen

- **Note relation (R04):** `owner_tag = k_owner^2`, `C_note = a + owner_tag + rho`,
  `N = k_owner*rho`, `a = a_exit`, over the BN254 base field.
- **Fixture:** `owner_tag=9`, `C_note=100014`, `N=15`, `a_exit=100000`. Witness
  `w=(x0,k_owner,rho,a)=(1,3,5,100000)`.

1. **Fund.** Generate a Bitcoin key, derive its Taproot output (BIP341, no script tree),
   and fund it with 101,000 sats. Core derives the address from `rawtr(Q)`. The block
   that confirms the funding is the snapshot the fixture is frozen at.
2. **Encrypt.** Emit the four R04 coefficient rows. Run Algorithm 1 for that relation,
   then encrypt a field element `mu` with Algorithm 2, all from a recorded seed.
3. **Wrap the key.** Derive `K` with HKDF from the 32-byte big-endian encoding of `mu`,
   then XChaCha20-Poly1305-encrypt the 32 key bytes. The associated data binds the note
   constants, the snapshot, the funding outpoint, the recipient and the amounts.
4. **Unlock.** Algorithm 3 recovers `mu` from the ciphertext and the note opening alone,
   which unwraps the key. `unlock` accepts no setup value.
5. **Spend.** Sign a key-path spend of 100,000 sats to the recipient with a 1,000-sat fee,
   using only the recovered key. Core accepts it, mines it and reports the same txid as
   the local computation.

Mocked decryption or a host-language verify-then-release shortcut does not count, and
neither is used: the spend re-derives its funding script from the recovered key.

## Checks

Every run asserts these against Core and records them in `.demo/result.json`:

| Check | Meaning |
| --- | --- |
| `coreDerivesFundingScript` | Core's address for `rawtr(Q)` has the script computed locally. |
| `fundingInSnapshot` | The funding transaction is in the fixture's snapshot block. |
| `recoveredKeyMatchesSetup` | The key unlocked from the note witness equals the setup key. |
| `mempoolAccepted` | `testmempoolaccept` accepts the locally signed spend. |
| `feeMatches` | Core reports a 1,000-sat fee. |
| `coreTxidMatchesLocal` | `sendrawtransaction` returns the locally computed txid. |
| `minedTxidMatchesLocal` | The mined block contains that txid. |
| `spendConfirmed` | The spend has at least one confirmation. |
| `coreHexMatchesLocal` | Core stores exactly the bytes signed locally. |
| `fundingOutpointSpent` | `gettxout` returns null for the funding outpoint. |
| `recipientReceivedPayment` | The recipient wallet received exactly 100,000 sats. |

## Tests

```sh
pnpm typecheck
pnpm test:unit   # 82 tests: field, AADP (R01), envelope, note (R04), fixture, unlock, Taproot, transactions
pnpm test:e2e    # the whole demo against a throwaway bitcoind
```

The Taproot tweak, the BIP341 signature message, the sighash and the signature are
checked byte for byte against the official BIP341 vectors, pinned in
[`test/fixtures/bip341-vectors.json`](test/fixtures/bip341-vectors.json).

## Roadmap

| Phase | Track | Depends on | Goal | Status |
| --- | --- | --- | --- | --- |
| P00 Freeze the experiment | core | — | Make the smallest claim reproducible. | Done |
| P01 Recover a local envelope secret | core | P00 | Exercise real AADP decryption without a note system or Bitcoin integration. | Done |
| P03 Fix one educational note | core | P00 | Define a minimal amount/owner/opening relation tied to the one local funding fixture. | Done |
| P04 Decrypt from the toy note witness | core | P01, P03 | Connect the four-row note relation to actual AADP matrix generation, encryption and recovery. | Done |
| P02 Spend one native regtest UTXO | core | P04 | Connect the recovered key to an ordinary Bitcoin transaction. | Done |
| P05 Reconstruct a proof-system adapter if needed | deferred | P03 | Recreate missing proof-system components from their equations. | Deferred |
| P06 Optionally release one transaction signature | deferred | P02 | Demonstrate transaction binding without delivering the unrestricted Bitcoin key. | Deferred |
| P07 Optionally reuse the existing note-proof baseline | deferred | P00 | Study note privacy and replay independently of AADP. | Deferred |

## Interface

```text
prepare(fixture, btc_sk) -> ciphertext, envelope, witness, setup attempt, cofactor
unlock(ciphertext, envelope, witness) -> recovered_btc_key
buildSpend(fixture, recovered_btc_key) -> signed transaction
```

| File in `.demo/` | Contents |
| --- | --- |
| `fixture.json` | Manifest (Node, Core), setup seed, note opening, block snapshot, funding outpoint, recipient script and amounts. Setup side: it holds known test secrets. |
| `witness.json` | The R04 assignment in canonical coordinate order. |
| `ciphertext.bin` | Mhat_0..Mhat_3 as dense 32-byte big-endian entries: exactly 10,368 bytes. |
| `envelope.json` | Nonce, AEAD ciphertext and associated data. |
| `result.json` | Txids, the raw spend, the setup attempt, the cofactor and every check. |

The Bitcoin secret key is never written to disk.

## Requirements

- Node 24 and pnpm 10
- Bitcoin Core 32.1, with `bitcoind` and `bitcoin-cli` on `PATH` (regtest only)

## v1 vs v2

| | [v1](../v1/README.md) | v2 |
| --- | --- | --- |
| Units | Simulated; no peg, no redemption | Native regtest BTC |
| Mechanism | Groth16 proof per transfer, `OP_RETURN` envelope, client-side replay | AADP witness encryption releases a Bitcoin key that signs an ordinary spend |
| Scope | Private transfers between notes | One note, one UTXO, one spend |
| Status | Implemented | Implemented |

## Layout

```
v2/
├── README.md
├── docs/
│   ├── codex_plan.md      plan: fixture, relations R01–R05, phases, checks
│   ├── claude_plan.md     implementation plan: milestones M0–M5
│   └── research.md        claims, limits, sources and measurements
├── scripts/demo.sh        fresh regtest node + the whole path
├── src/
│   ├── constants.ts       field, AADP shape, domain tags, amounts
│   ├── field.ts           F_q arithmetic, matrices, determinant, seeded sampler
│   ├── relation.ts        constraints a·b = c·d over linear forms
│   ├── aadp.ts            Algorithms 1–3
│   ├── envelope.ts        HKDF + XChaCha20-Poly1305 under mu
│   ├── note.ts            the R04 toy note
│   ├── fixture.ts         the frozen fixture and the envelope's associated data
│   ├── unlock.ts          prepare (setup) and unlock (recipient)
│   ├── taproot.ts         BIP341 key tweak and output script
│   ├── transaction.ts     serialization, txid, SIGHASH_DEFAULT, signing
│   ├── rpc.ts             bitcoind JSON-RPC client
│   ├── demo.ts            the pipeline and its checks
│   ├── artifacts.ts       writes .demo/
│   ├── json.ts            JSON readers and formatting
│   └── main.ts            `pnpm demo` entry point
└── test/
    ├── unit/              one file per module
    ├── e2e/demo.test.ts   the demo against a throwaway bitcoind
    ├── fixtures/          pinned BIP341 vectors
    └── helpers/           test fixture, vector decoder, regtest node
```
