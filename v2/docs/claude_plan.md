# Plan: ZBTC v2: implement the toy note → AADP → Taproot regtest spend

## Status

All milestones are done, one commit each on `feat/v2-aadp`. `pnpm demo` passes its eleven
checks, and `pnpm test:e2e` passed twice in a row.

| Milestone | Commit |
| --- | --- |
| M0 docs | `docs: restructure the v1 and v2 docs` |
| M1 AADP core | `feat(v2): add aadp matrix encryption over the bn254 base field` |
| M2 note unlock | `feat(v2): unlock the wrapped key from the r04 note witness` |
| M3 Taproot | `feat(v2): sign a taproot key-path spend with the recovered key` |
| M4 regtest demo | `feat(v2): run the note-to-spend demo on regtest` |
| M5 docs | `docs(v2): document the implemented demo` |
| Follow-up | `feat(v2): freeze the funding block snapshot in the fixture` |

Deviations from the plan below:

- `src/rpc.ts` moved from M3 to M4, the first milestone that calls a node.
- `prepare(fixture, secretKey)` takes the key it wraps as an argument; the fixture stays
  free of the Bitcoin key.
- Added `src/json.ts` (JSON readers), `src/artifacts.ts` (writes `.demo/`) and
  `src/main.ts` (the `pnpm demo` entry point), so `src/demo.ts` stays free of file I/O.
- The ciphertext artifact is `ciphertext.bin`, the dense 10,368-byte encoding.

## Context

`v2/docs/codex_plan.md` specifies a functional demo. The witness of a toy note (R04) drives real AADP matrix decryption. The decryption recovers `mu`, which unwraps a Bitcoin key through HKDF+AEAD. That key signs a native regtest spend: fund 101,000 sats, pay 100,000 and leave a 1,000-sat fee. The required phase order is P00 → P01 → P03 → P04 → P02.

Codex started this work and did not finish it. Its code is 444 lines of plain JS, uncommitted, in worktree `/private/tmp/zbtc-v2-implementation`. That worktree is on branch `feat/v2-aadp`, at commit `440d7da` ("refactor: separate versioned experiments"), which sits on top of `refactor/clean-code`. An audit found:

| Area | State |
| --- | --- |
| Algorithms 1–3 (`aadp.js`) | Correct, and matches the official Sage toy (U block, xi for each constraint and variable, Δ at (k-1,k-1), ratio recovery). |
| Field (`field.js:3`) | **Wrong.** It uses the BN254 scalar field r, but the spec requires the base field q (…208583). |
| R04 (`note.js:28`) | Row 2 uses `D=e0` where the spec says `D=0`. |
| Bitcoin key (`bitcoin-key.js`) | **Bug:** `createECDH` strips leading zeros, so about 0.45% of keys come out at 31 or 30 bytes and the demo fails. |
| Spend (`demo.js`) | P2WPKH signed by Core's wallet. It is not Taproot, computes no local txid, and has never been run. |
| P00 | No recorded seed, no manifest, and the AEAD associated data does not bind the outpoint or recipient. |
| Style | A 40-line `runDemo`, magic numbers, float BTC amounts, no types. |

The user wants this continued as a plan, with short commits (one per milestone), Clean Code, and the PR and comments in English with no AI attribution.

## Decisions

- **Port to TypeScript, matching v1:** strict tsconfig, vitest, `@noble/*` 2.4.0, and exact version pins. Codex's algebra is kept and its bugs fixed. The reasons are that the user asked for Clean Code and types, and that v1 already uses this stack.
- **No Sage:** Algorithms 1–3 are reconstructed with bigint over q. The matrices are 9×9, so Sage adds nothing.
- **Real Taproot key path:**
  - written by hand: the BIP341 tweak, the transaction serialization, the txid and `SIGHASH_DEFAULT`;
  - from `@noble/curves`: `schnorr` and `utils.taggedHash`;
  - from Core: the address via `getdescriptorinfo` + `deriveaddresses` on `rawtr(Q)`.
  - No new Bitcoin library is installed.
- **Copy, don't import, from v1:**
  - `v1/src/rpc.ts` lines 9–228, because importing it pulls in poseidon-lite through `crypto.ts`;
  - `v1/test/helpers/regtest.ts` whole;
  - the `v1/scripts/demo.sh` pattern.
- **v2 node:** its own datadir `v2/.regtest` and RPC port `18643`, so it never wipes or collides with a v1 node.
- **Git:**
  - one commit per milestone, as a one-line Conventional Commit with no body;
  - never `Co-Authored-By` or "Generated with";
  - PRs are stacked: `refactor/clean-code → main`, then `feat/v2-aadp → refactor/clean-code`.

## Step 0: workspace (no commit)

1. Move the worktree out of `/private/tmp`: `git worktree move /private/tmp/zbtc-v2-implementation /Users/glitch/Development/ZCASH/ZBTC-v2`.
2. Move Codex's untracked JS (`v2/src/*.js`, `v2/test/*.js`, `v2/package.json`) to `v2/.codex-prototype/`. Exclude that directory locally in `.git/info/exclude`. It is the porting reference and is deleted in M4.
3. Implementation route: for each milestone, delegate one writer. I verify, then commit.

## Milestones

### M0: docs (`docs: restructure the v1 and v2 docs`)
- Bring over the docs work from the main checkout:
  - root `README.md`;
  - `v1/README.md` and any `v1/docs/*` files the branch doesn't track yet (`claude_plan.md`, the `.excalidraw` diagrams);
  - `v2/README.md`, `v2/docs/codex_plan.md` and `v2/docs/research.md`.
- Add this plan as `v2/docs/claude_plan.md`, mirroring v1, and list it in the v2 README Layout.
- Acceptance: all relative links resolve, and `rg private-bitcoin-poc-plan` returns nothing.

### M1: P01, the AADP core (`feat(v2): add aadp matrix encryption over the bn254 base field`)
- Scaffold `v2/package.json`, `pnpm-lock.yaml`, `tsconfig.json` and `vitest.config.ts`, mirroring v1 without `pool: 'forks'`. Scripts: `typecheck`, `test:unit`, `test:e2e`, `demo`.
- **`src/constants.ts`:**
  - `BASE_FIELD_MODULUS` (q) and `FIELD_ELEMENT_BYTES`;
  - domain tags `'zbtc/v2/…'`;
  - `FUNDING_SATS`, `PAYMENT_SATS` and `FEE_SATS` as bigint;
  - `RPC_PORT`.
- **`src/field.ts`:** `mod`, `inverse`, `determinant` (Gaussian elimination) and `leadingMinor`. It also has a seeded sampler: `sha256(seed‖tag‖counter)` with rejection sampling, so a recorded seed reproduces the setup (P00).
- **`src/relation.ts`:** `LinearForm` and `Constraint {a,b,c,d}` meaning `a·b = c·d`, with `evaluate`.
- **`src/aadp.ts`:**
  - `generateMatrices` (Algorithm 1), with a `uBlock` helper and `xi` for each constraint and variable;
  - `encrypt` (Algorithm 2), using a named `delta`;
  - `decrypt` (Algorithm 3: `det(E)/det(minor)`, throwing `ZeroCofactorError`);
  - `recoveryCofactor` and `ciphertextBytes`.
- **`src/envelope.ts`:** HKDF-SHA256 over the fixed-width encoding of `mu`, then `xchacha20poly1305` with a random 24-byte nonce. The associated data is a canonical encoding of the fixture metadata. `unseal` returns `null` on failure, as in v1.
- **Tests:**
  - R01 rows give 4, 8, 32, 16 and 64; `mu` is recovered; the size is 15,488 bytes;
  - `det(S(w)) = 0`;
  - one changed witness, recorded only as an illustration;
  - envelope round trip, including a key with a leading zero byte;
  - tampered associated data makes `unseal` return `null`.

### M2: P03 + P04, the note unlocks the key (`feat(v2): unlock the wrapped key from the r04 note witness`)
- **`src/note.ts`:** R04 exactly as in the spec (row 2 `D=0`), with the spec's names in camelCase (`ownerKey`, `rho`, `ownerTag`, `noteCommitment`, `nullifierTag`, `exitAmount`). The witness is `(x0, ownerKey, rho, a)`.
- **`src/fixture.ts`:** the `Fixture` type, the manifest (Node and Bitcoin Core 32.1 versions, the seed, the note constants and amounts) and its read/write.
- **`src/unlock.ts`:**
  - `prepare(fixture)` returns `{ciphertext, envelope, witness}`. It checks the recovery cofactor during setup; if the cofactor is zero, it moves to the next recorded seed and logs the attempt.
  - `unlock(ciphertext, envelope, witness)` returns the key bytes and never reads setup values.
- **Tests:** rows give 9, 0, 15 and 100000; the exact key is recovered; the ciphertext is 10,368 bytes; one changed witness is recorded.

### M3: P02, the Taproot primitives (`feat(v2): sign a taproot key-path spend with the recovered key`)
- **`src/taproot.ts`:**
  - `generateSecretKey`, always 32 bytes, from `schnorr.utils.randomSecretKey`;
  - `xOnly`;
  - `tweakPublicKey` and `tweakSecretKey` (TapTweak with no script tree; parity negation);
  - `outputScript` (`OP_1 0x20 Q`).
- **`src/transaction.ts`:** the `Transaction` type, `serialize` (with and without witness), `txid` (double SHA-256, reversed), `sighashDefault` (BIP341 signature message, any number of inputs) and `signKeyPath`.
- **`src/rpc.ts`:** a copied subset of v1's `BitcoinRpc`, plus `getDescriptorInfo`, `deriveAddresses`, `getAddressInfo`, `getTxOut` and `testMempoolAccept`.
- **Tests:** BIP341 `wallet-test-vectors.json`: the scriptPubKey tweak vectors and one keyPathSpending sighash/signature vector. A subset is stored in `test/fixtures/bip341-vectors.json`, taken from a pinned bitcoin/bips commit.

### M4: P02, the end-to-end demo (`feat(v2): run the note-to-spend demo on regtest`)
- **`src/demo.ts`:** a pipeline of small steps:
  1. `fundTaprootOutput` (101,000 sats, finding the vout by its script);
  2. `prepare`;
  3. `unlock`;
  4. `buildSpend` (100,000 to the recipient, 1,000 fee);
  5. `testmempoolaccept`, then `sendrawtransaction`, then mine;
  6. `verifySpend`;
  7. `writeArtifacts`.
- **Artifacts** go to `v2/.demo/`, which is gitignored: `fixture.json`, `witness.json`, `envelope.json`, the ciphertext and `result.json`. `result.json` holds the cofactor, the raw transaction, the local and Core txids, and the checks.
- **`scripts/demo.sh`:** follows v1's pattern, with datadir `v2/.regtest`, `RPCPORT=18643` and `KEEP=1`.
- **`test/helpers/regtest.ts`** is copied from v1, and **`test/e2e/demo.test.ts`** asserts:
  - the local txid equals Core's txid and the mined txid;
  - the spend has at least 1 confirmation;
  - the recipient output is 100,000 sats;
  - `gettxout` on the funding outpoint returns `null`;
  - the fee is 1,000 sats.
- Delete `v2/.codex-prototype/`.

### M5: docs (`docs(v2): document the implemented demo`)
- **`v2/README.md`:** status, quickstart (`pnpm install`, `pnpm demo`), tests and the code layout.
- **`codex_plan.md`:** tick P00–P04/P02 and set the status to implemented.
- **`research.md`:** add a measurements section with the artifact size, timings and the observed cofactor.
- **Root `README.md`:** set v2 to Implemented.

## Code conventions (from v1's Clean Code pass)

- **Files:** each opens with a module header comment describing its purpose and data flow, split into `// ---- Section ----` blocks.
- **Constants:** no magic literals. Name them in SCREAMING_SNAKE with a suffix (`_BYTES`, `_SATS`, `_MS`), plus a one-line doc saying why.
- **Functions:** usually 5–25 lines. Long flows become named steps. Comments explain *why*, never *what*.
- **Names:** spelled out; math names from the spec stay (`mu`, `xi`, `delta`). Amounts are sats as bigint and are never floats.
- **Modules:** ESM with `.js` suffixes, `node:` prefixes, named exports only, and inline `type` imports.
- **Errors:** `RangeError` for bad input; `Error` subclasses with `readonly` fields for domain failures.

## Verification

Before each commit, in `v2/`, run `pnpm typecheck && pnpm test:unit`. From M4 on, also run `pnpm test:e2e`.

At the end:
1. `pnpm demo` exits 0 and prints the txid, with every check passing.
2. Run `pnpm test:e2e` twice and get green both times.
3. `git log --oneline refactor/clean-code..feat/v2-aadp` shows the layout commit plus M0–M5, each one line, with no attribution.
4. `rg -n 'Co-Authored|Generated with'` over the commits and PR bodies returns nothing.

## Delivery

1. Push `refactor/clean-code`. Open its PR against `main`: English, a short summary and how to review it.
2. Push `feat/v2-aadp`. Open the v2 PR with base `refactor/clean-code`. Its body has a summary, the review path one milestone commit at a time, what is out of scope (P05–P07, security), and the verification steps.
3. The main checkout still holds the docs changes uncommitted, and they are now redundant with M0. Tell the user; do not discard them automatically.
