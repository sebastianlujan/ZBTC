# Plan: ZBTC — minimal Shielded Bitcoin transfer layer on regtest (case B)

## Context

The user wants a working private-transfer demo on Bitcoin regtest only (no other chain, no
bridge, no federation). It is inspired by the Shielded Bitcoin paper (Shikhelman, Komarov,
Moskvin, Sep 2026), PIPEs v2, AADP, Shielded CSV and zkCoins. The user also wants an
evidence-backed account of the limits beyond the papers. They chose **our own minimal
implementation** (TypeScript + Circom), using `harshjv/shielded-bitcoin-poc` only as a
cross-check reference.

Research findings that set the scope (all verified in the sources):
- **The Shielded Bitcoin internal layer is implementable today.** It needs only:
  - one OP_RETURN envelope per transfer, carrying a Groth16 proof;
  - a nullifier rule `nf = H(sk_nf, ρ, pos)`, with `sk_nf` derived in-circuit (§9 p.15);
  - deterministic replay in Bitcoin order, where the first nullifier wins (§15 p.23, A.7).
- **BTC entry and exit are out of the paper's scope** (§1.2, §20.4). Genesis is a declared
  inventory (p.3).
- **PIPEs v2 cannot carry native BTC yet.**
  - Once its one-shot Schnorr key is released, there is no restriction on later spends
    (PIPEs v2 §1.1 p.3).
  - Its security assumes an honest Setup, with only a remark suggesting MPC/DKG.
  - AADP witness encryption has only a modeling script, not an implementation: ~338 TiB
    ciphertext, ~2,000 core-hours to decrypt, and heuristic security.
- **Shielded CSV is spec-only.** It is Rust pseudocode where every primitive is
  `unimplemented!()`, and it needs a bridge for BTC.

**What the PoC demonstrates:** case B. Private notes with *simulated units*, anchored and
ordered by Bitcoin and validated client-side. It is NOT private native BTC (case C), and every
document must say so.

Environment:
- The repo `/Users/glitch/Development/ZCASH/ZBTC` is empty.
- Already installed: circom 2.2.3, node 24, pnpm, docker.
- Missing: bitcoind and snarkjs.

## Key design decisions

1. **Ownership is proven by hash plus the ZK proof, with no signature.**
   - `owner = Poseidon(DOM_OWN, sk_spend)` and `sk_nf = Poseidon(DOM_NFK, sk_spend)`.
   - The proof is tied to this transfer by its public inputs `[root, hBody, nf[2], cm[2]]`.
   - A signature would only be needed for delegated proving, threshold ownership, or binding
     data outside `h_body`.
2. **Note encryption happens outside the circuit**, so **leaf = cm** =
   `Poseidon(DOM_CM, v, owner, rseed)`, published as a public input.
   - The paper proves encryption in-circuit. Without that, `cm` must commit to the value,
     otherwise a spender could claim any value: inflation.
   - Encryption is X25519 + HKDF-SHA256 + ChaCha20-Poly1305, with aad = cm.
3. **`h_body` is a public input.** It binds epk, ct and h_anchor, which the other public
   inputs do not cover. snarkjs IC rows already bind it; a `hBody²` constraint is added as
   insurance.
4. **Fixed 2-in/2-out transfers with zero-value dummies.** Merkle depth is 20. Every value is
   range-checked with `Num2Bits(64)` and `pos` with `Num2Bits(20)`. No `LessThan`, no `<--`.
5. **Genesis** is a `genesis.json` inventory of plaintext `(v, owner, rseed)` entries with
   Σv = totalSupply. There is no issuer key and no mint authority.
6. **No persistent indexer database.** State is whatever replay produces. Per-block undo
   records exist only for the long-running instances in the reorg tests.
7. **Wallet state is derived from (seed, replay, mempool, locks).** Only the locks are stored,
   so seed recovery works.
8. **Node:** Homebrew `bitcoin` 32.1 runs natively. Tests spawn a bitcoind with a temp
   datadir and random ports.

## Layout

```
package.json tsconfig.json vitest.config.ts(pool:'forks') .gitignore README.md
circuits/transfer.circom  circuits/merkle.circom
circuits/variants/norange.circom  circuits/variants/nosquare.circom   # test-only unsafe variants
scripts/circuit.sh  scripts/demo.sh
src/constants.ts crypto.ts tree.ts codec.ts prover.ts rpc.ts indexer.ts wallet.ts cli.ts
test/helpers/{regtest,world,craft,rerandomize}.ts
test/unit/{codec,crypto,tree}.test.ts  test/circuit/transfer.test.ts
test/e2e/{publish,indexer,happy-path,double-spend,soundness,reorg,agreement,recovery}.test.ts
docs/research.md
```

**Dependencies**, pinned exactly:
- `snarkjs@0.7.6` and `circomlib@2.0.5`
- `poseidon-lite@0.3.0`
- `@noble/curves`, `@noble/ciphers`, `@noble/hashes`
- dev tools: `tsx`, `typescript`, `vitest`. If the latest versions cause friction, fall back
  to TS 5.9 / vitest 3.x.

**Size estimate:** about 110 lines of circom, about 1.1k lines in src and about 1k lines of
tests.

## Circuit `Transfer(2,2,20)`

- **Public inputs:** `[root, hBody, nf0, nf1, cm0, cm1]`, in this order. Test C1 asserts the
  order matches the codec.
- **Private inputs:** `skSpend`, plus `inV, inRseed, inPos, inPath[20]` for each input and
  `outV, outOwner, outRseed` for each output.

Constraints:
- Derive `owner` and `skNf` from `skSpend`.
- For each input:
  - `Num2Bits(64)(v)`;
  - `inCm = Poseidon(DOM_CM, v, owner, rseed)`;
  - `MerkleRoot(20)`, which applies `Num2Bits(20)` to pos;
  - `(rootC - root) * v === 0`, so a dummy input skips only the membership check;
  - `nf === Poseidon(DOM_NF, skNf, rseed, pos)`.
- For each output: `Num2Bits(64)(v)` and `cm === Poseidon(DOM_CM, v, outOwner, rseed)`.
- `Σin === Σout`. Each side is below 2^65, so the sum cannot wrap mod p.
- `nf0 ≠ nf1`, enforced with `IsZero`.
- `hBody²`.

Size and setup:
- About 12.3k constraints.
- Trusted setup uses `ppot_0080_15.ptau` (37.8 MB; check its size and record its sha256)
  plus one dev phase-2 contribution. This setup is insecure and documented as such.

## Envelope: 572 bytes in a single OP_RETURN (PUSHDATA2)

| off | len | field |
|---|---|---|
| 0 | 4 | magic `zbtc` |
| 4 | 1 | version 0x01 |
| 5 | 1 | type 0x01 |
| 6 | 4 | h_anchor (u32 LE) |
| 10 | 1 | n_in = 2 |
| 11 | 1 | n_out = 2 |
| 12 | 64 | nf0, nf1 |
| 76 | 64 | cm0, cm1 |
| 140 | 64 | epk0, epk1 (X25519) |
| 204 | 112 | ct0, ct1: AEAD(v u64 ‖ rseed) + tag |
| 316 | 256 | π, uncompressed, in snarkjs order |

- `body = bytes[0,316)`.
- `h_body = first 31 bytes of SHA256("zbtc/v1/body" ‖ body)`, read as a big-endian integer.
- Every field element must be `< r` and every proof coordinate `< q`. Anything else is a
  parse error.
- π_A and π_C must be on G1 and not the point at infinity. π_B must be on G2, in the G2
  subgroup (checked with `@noble/curves` bn254), and not the point at infinity. Anything else
  is `E_PARSE`. This check is needed because snarkjs `isWellConstructed` only checks
  on-curve.
- Keys come from HKDF over the seed: `sk_spend` (64 bytes mod r) and `sk_enc`.
- Address format: `zbtcrt` + hex(owner) + hex(pk_enc).

## Indexer (replay); paper §15 / A.7

**Genesis:** load the cm values from the inventory, check Σv = supply, then set R[S−1].

**`applyBlock(H)`** processes each transaction in block order:
0. Find the vouts that are `OP_RETURN` with exactly one minimal push starting with `zbtc`.
   None: ignore the tx. More than one: `E_MULTI`.
1. Canonical parse, else `E_PARSE`.
2. Recompute `h_body`.
3. Check `max(S−1,H−100) ≤ h_anchor ≤ H−1`, else `E_ANCHOR`. Then
   `r_anchor = R[h_anchor]`.
4. Check `nf0≠nf1` (`E_NF_DUP`) and that neither is already in N (`E_NF_SPENT`).
5. Run `groth16.verify` on the public inputs, else `E_PROOF`.
6. Apply atomically: insert the nfs, append cm0 then cm1 and record their positions, and
   write the undo record.

After the last transaction, store R[H], blockhash[H] and treeSize[H].

Rules:
- Duplicates are detected **only by nullifier**, never by txid or proof bytes.
- Rollback triggers on a hash or previousblockhash mismatch. It truncates the tree, deletes
  the nfs and pops the accepted entries.

**State digest** = SHA256 over:
- height and tipHash
- |T| and root
- the hash of the sorted nullifier set
- the hash of the R[h] map
- the hash of the accepted history
- a profile hash covering vkey, genesis, W, K and DEPTH

Replay never reads the mempool, the clock, or Map iteration order.

## Wallet

**Receiver checks:**
1. Try to decrypt with `X25519(sk_enc, epk)`; on failure, skip silently.
2. The plaintext must be 40 bytes and `rseed < r`.
3. **`cm' == cm`**, recomputed with the receiver's own owner.
4. Take pos from replay.
5. Before proving, check the path locally against R[anchor].

**Note states** (derived):

| State | Condition |
|---|---|
| `candidate` | Seen in the mempool; never counted in the balance |
| `confirmed(k)` | Accepted, with k confirmations |
| `spendable` | k ≥ K, nf ∉ N, no lock, and a witness exists at treeSize[a] |
| `pending-spend` | A local lock holds its nf |
| `spent` | nf ∈ N on the active chain |

**Locks are released** when:
- nf ∈ N, or
- the transaction left the mempool more than 10 blocks ago, or
- the anchor root changed or is outside the window. In that case the transfer is rebuilt.
  A rebuild cannot double-spend: if pos is the same the nf is the same, and if pos changed
  the old proof fails.

**`buildTransfer`:**
1. Select 1–2 notes and pad with a dummy input.
2. Create the payment and change outputs, shuffled.
3. Prove, verify locally, publish, and write the lock.

**Publishing:** `createrawtransaction [] [{"data":hex}]` → `fundrawtransaction` on the
actor's `<name>-fee` wallet → `signrawtransactionwithwallet` → `sendrawtransaction`.

## Node and demo

```
brew install bitcoin   # 32.1
bitcoind -regtest -datadir=$PWD/.regtest -daemon -server=1 -txindex=1 -fallbackfee=0.0002 \
  -acceptnonstdtxn=0 -listen=0 -rpcport=18443      # cookie auth; datacarriersize default (100k, v30+)
```

`scripts/demo.sh`:
1. `zbtc init`, which mines 101 blocks.
2. Create wallets for alice, bob and carol.
3. `genesis alice=100`, then mine.
4. Send alice→bob 30, mine, send bob→carol 10, mine.
5. Balances must be **70/20/10 units**.
6. Print `index --digest`.

## Test matrix (expected outcomes)

**Circuit** (`test/circuit/transfer.test.ts`):

| ID | Case | Expected |
|---|---|---|
| C1 | Valid transfer | Verifies; signal order and JS cm/nf/root match the circuit |
| C2 | Overflow near p | Throws |
| C3 | Same input on the `norange` variant | **Verifies** (shows the range checks are what prevents inflation) |
| C4–C8 | Wrong nf; wrong root; Σ mismatch; someone else's key; same note twice | Each throws |
| C9 / C9b | Each public input +1; h_body tweak on `nosquare` | `false` |
| C10 | nf + r alias | `false` (CVE-2023-33252 regression) |
| C11 | Constraint count | Logged |
| C12 | pos ≥ 2^20 | Throws |

**Unit tests:**
- codec: round-trip; length ±1, values ≥ r or q, bad version, non-minimal push and
  `E_MULTI` are all rejected.
- crypto: wrong key, tampered ct, or a cm mismatch each return null or are rejected.
- tree: an old-prefix witness verifies; truncate restores the previous root.

**E2E on regtest** (each file starts its own bitcoind):

| File | Cases and expected outcomes |
|---|---|
| publish | The 576-byte OP_RETURN is relayed as standard |
| indexer | Accept; republish → `E_NF_SPENT`; after invalidateblock, the digest equals a fresh replay |
| happy-path | Alice→Bob→Carol ends 70/20/10, Σ=100, with all state transitions observed |
| double-spend | `generateblock [A,B]` → A wins; `[B,A]` → B wins; across blocks, the later one gets `E_NF_SPENT`; mempool race → exactly one accepted; crafted nf0==nf1 → `E_NF_DUP` |
| soundness | out>in rejected; a `norange` proof on-chain → `E_PROOF`; random π → `E_PROOF`; flipping a byte of anchor, nf, cm, epk or ct → `E_PROOF`; front-running by copying nfs+π with new outputs → `E_PROOF`; a re-randomized copy mined first is accepted and harmless (same notes); garbage ct is **accepted but the funds are lost** (deviation); anchors H−1 and H−100 accepted, H and H−101 → `E_ANCHOR` |
| reorg | A reorg removing a spend → note back to candidate, later re-accepted with the same proof; a reorg flipping the winner → Carol gets it, re-mining A → `E_NF_SPENT`; a stale anchor → `E_PROOF` and the rebuild is accepted |
| agreement | Indexer on node A (incremental, through a reorg), indexer on peered node B (`-txindex=0`), and the CLI subprocess all produce an **identical digest** |
| recovery | `Wallet.fromSeed` restores the same notes, positions and balances |

Test-construction rules:
- Separate fee wallets, so the double-spend happens at the shielded layer and not at the
  Bitcoin layer.
- Use `generateblock` with explicit transaction lists to control order.

## Milestones (each independently verifiable)

| # | Work | Check |
|---|---|---|
| M0 | `brew install bitcoin`; pnpm with pinned deps, tsconfig, vitest | `bitcoind -version` shows 32.1; `pnpm typecheck` |
| M1 | Circuit, constants, crypto (Poseidon part), tree, prover, `circuit.sh`. **No Bitcoin.** | `pnpm circuit && vitest run test/unit/tree.test.ts test/circuit` is green and shows ~12.3k constraints |
| M2 | codec, encryption, rpc, `helpers/regtest` | `vitest run test/unit test/e2e/publish.test.ts` |
| M3 | Indexer: genesis, apply, rollback, sync, digest | `vitest run test/e2e/indexer.test.ts` |
| M4 | Wallet, CLI, demo | `pnpm demo` ends at 70/20/10 with a digest; happy-path and recovery green |
| M5 | Adversarial suite, `craft` and `rerandomize` helpers | `pnpm test:e2e` all green |
| M6 | `docs/research.md` and README | Every claim cites a test ID or a paper page |

## `docs/research.md` outline (answers the original research prompt)

1. **Conclusion:** what this PoC proves (case B) and what it does not (case C).
2. **How the papers relate**, with page citations:
   - PIPEs v2: witness encryption of a Schnorr key, unlocked by a binary NP condition.
   - AADP: the witness-encryption candidate, existing only as estimates.
   - Shielded Bitcoin: the shielded layer, without entry or exit.
   - Shielded CSV: PCD plus signed 64-byte nullifiers, needs a bridge.
3. **Distinctions:**
   - Witness encryption vs. a server that verifies a proof and then signs.
   - Key release vs. a persistent covenant.
   - Who controls the UTXO, and the recovery path.
4. **The 9 questions from the prompt**, answered against our implementation:
   - issuance;
   - antecedents: global replay over on-chain data replaces recursion, at O(chain) cost;
   - key ↔ owner;
   - nf binding;
   - mempool front-running;
   - invalid or missing data;
   - agreement between clients;
   - reorgs;
   - recovery.
5. **The A/B/C taxonomy:** what is hidden, from whom, and what stays visible in each case.
   - Fee-funding inputs link publications.
   - Timing.
   - The regtest anonymity set is only 1–3 leaves.
6. **Where each tool fits:**
   - Circom/snarkjs: defines the statement and verifies it locally. Bitcoin never enforces it.
   - BitVM2: optimistic verification through disputes; needs 1-of-n honest participants and
     operator liquidity.
   - Silent Payments (BIP-352): hides only receiver addresses; not in Core 32.1.
7. **Consensus vs. policy:** OP_RETURN size limits are relay/mining policy (v30+), not
   consensus. Working on regtest does not prove mainnet viability.
8. **Measurements:** constraints, prove/verify ms, zkey size, envelope bytes, vsize, and
   replay ms per block.
9. **The next obstacle toward case C:** a succinct replay-validity proof (§22.2), followed by
   an enforcement layer. Every candidate today brings a new trust assumption: PIPE Setup and
   heuristic WE, BitVM2 1-of-n, or a FROST committee.

## Deviations from the Shielded Bitcoin paper

| Area | Paper | ZBTC |
|---|---|---|
| Value | sats via PIPEs | simulated units |
| Leaf | `H_leaf(salt,h_body,j,pk_eph,ct,h_aux)` | `cm = Poseidon(v,owner,rseed)` |
| Encryption | proven in-circuit | off-circuit; a garbage ct is accepted and the receiver loses the note |
| Keys | diversified, HKDF tree | `owner = H(sk_spend)` plus X25519 enc key; no diversifiers |
| `ct_out` | included | omitted: seed recovery loses details of outgoing payments |
| Proof | 192 B compressed | 256 B uncompressed |
| Envelope | 610 B | 572 B |
| Setup | ceremony | one dev contribution: whoever ran it can mint |
| Fees | future PIPE vault | per-actor bitcoind wallet, which links publications |

## Execution route

- The work is **delegated direct**: one writer sub-agent per milestone, run sequentially.
- After each milestone I run its check command myself before starting the next.
- Commits are conventional, one per milestone, with no AI attribution. I commit only if you
  ask.

## Verification (end-to-end)

1. `pnpm circuit`: builds the circuit and the dev setup, and prints the constraint count.
2. `pnpm test:unit && pnpm vitest run test/circuit`.
3. `pnpm test:e2e`: spawns its own bitcoind 32.1 nodes and runs every adversarial case above.
4. `pnpm demo`: Alice→Bob→Carol ends at 70/20/10 units and prints a state digest. Running
   `zbtc index --digest` from a fresh process must print the same digest.
5. Check by hand with `bitcoin-cli getrawtransaction <txid> 1`: the OP_RETURN contains only
   nf, cm, epk, ct and π, with no amounts or addresses in clear.
