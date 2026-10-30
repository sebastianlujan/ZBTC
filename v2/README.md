# ZBTC v2

A planned functional demonstration on Bitcoin Core regtest. One toy note supplies the
witness for real AADP matrix decryption; the recovered secret derives an AEAD key that
decrypts a Bitcoin private key, and that key signs an ordinary spend of one native regtest
UTXO. The fixture funds 101,000 sats, pays 100,000 sats to a fixed recipient and leaves a
1,000-sat fee. Missing code is reconstructed from the AADP paper.

> **Planned, not implemented. This is not private BTC.** Nothing has been built or run.
> The note relation is deliberately insecure: a weak algebraic commitment with known
> secrets, not a secure hash. An honest setup operator knows every secret, including the
> Bitcoin key. The recipient receives the raw key, which can sign any spend, not only the
> demo transaction. Amounts, fees and the transaction graph stay visible on-chain, and one
> note gives no anonymity set. Do not use any of this with real value.

Status: **planned; not implemented**. Runtime validation: **not run**.

- Plan: [`docs/codex_plan.md`](docs/codex_plan.md): relations, fixture, phases, checks
  and stop conditions.
- Implementation plan: [`docs/claude_plan.md`](docs/claude_plan.md): TypeScript
  milestones M0–M5 and the verification route.
- Research: [`docs/research.md`](docs/research.md): claims, limits and sources.

## Demo in one screen

- **Note relation (R04):** `owner_tag = k_owner^2`, `C_note = a + owner_tag + rho`,
  `N = k_owner*rho`, `a = a_exit`, over the BN254 base field.
- **Fixture:** `owner_tag=9`, `C_note=100014`, `N=15`, `a_exit=100000`. Witness
  `w=(x0,k_owner,rho,a)=(1,3,5,100000)`.

1. **Fund.** Issue the single toy note R04 and fund its 101,000-sat regtest UTXO. Freeze
   the fixture; the setup operator is explicitly trusted.
2. **Encrypt.** Emit the four R04 coefficient rows and the opening assignment. Run
   Algorithm 1 for that relation, then encrypt a field element `mu` with Algorithm 2.
3. **Wrap the key.** Derive `K` with HKDF from a canonical fixed-width encoding of `mu`,
   then AEAD-encrypt the complete Bitcoin key bytes. Ciphertext and envelope stay in local
   files.
4. **Unlock.** Use the note-opening assignment in Algorithm 3 to recover `mu`, derive `K`
   and decrypt the key. The recipient flow consumes the recovered value, never a setup copy.
5. **Spend.** Sign an ordinary regtest spend of 100,000 sats to the fixture recipient with
   a 1,000-sat fee. Submit and mine it, then check the txid, the spent outpoint and the
   recipient output.

Mocked decryption or a host-language verify-then-release shortcut does not count. The demo
is complete only when regtest Core confirms the spend signed with the recovered key.

## Roadmap

| Phase | Track | Depends on | Goal |
| --- | --- | --- | --- |
| P00 Freeze the experiment | core | — | Make the smallest claim reproducible before implementing anything. |
| P01 Recover a local envelope secret | core | P00 | Exercise real AADP decryption without a note system or Bitcoin integration. |
| P03 Fix one educational note | core | P00 | Define a minimal amount/owner/opening relation tied to the one local funding fixture. |
| P04 Decrypt from the toy note witness | core | P01, P03 | Connect the four-row note relation to actual AADP matrix generation, encryption and recovery. |
| P02 Spend one native regtest UTXO | core | P04 | Connect the recovered key to an ordinary Bitcoin transaction. |
| P05 Reconstruct a proof-system adapter if needed | deferred | P03 | Recreate missing proof-system components from their equations. |
| P06 Optionally release one transaction signature | deferred | P02 | Demonstrate transaction binding without delivering the unrestricted Bitcoin key. |
| P07 Optionally reuse the existing note-proof baseline | deferred | P00 | Study note privacy and replay independently of AADP. |

Required order: **P00 → P01 → P03 → P04 → P02**. P05–P07 are deferred and do not gate
completion.

## Planned interface

Proposed calls and files; none exist yet.

```text
prepare(fixture) -> coefficients, ciphertext, envelope, witness
unlock(ciphertext, envelope, witness) -> recovered_btc_key
spend(fixture, recovered_btc_key) -> raw_transaction, result
```

| File | Contents |
| --- | --- |
| `fixture.json` | Field/relation identity, note constants, known test secrets, Bitcoin key/address convention, snapshot, funding outpoint, recipient and amounts. |
| `ciphertext` + `envelope.json` | Encrypted matrices and AEAD envelope, with encoding and associated-data convention. The recipient flow never reads `mu` or the original matrices from setup. |
| `witness.json` | The generated R04 assignment in canonical coordinate order. |
| `result.json` | Recovered-secret checks, cofactor status, raw spend, local and Core txids, confirmation, value and outpoint checks. |

## Requirements (planned)

- Bitcoin Core, regtest only
- SageMath

Versions are not chosen yet. P00 pins them in its source/environment manifest.

## v1 vs v2

| | [v1](../v1/README.md) | v2 |
| --- | --- | --- |
| Units | Simulated; no peg, no redemption | Native regtest BTC |
| Mechanism | Groth16 proof per transfer, `OP_RETURN` envelope, client-side replay | AADP witness encryption releases a Bitcoin key that signs an ordinary spend |
| Scope | Private transfers between notes | One note, one UTXO, one spend |
| Status | Implemented | Planned; not implemented |

## Layout

```
v2/
├── README.md
└── docs/
    ├── codex_plan.md   plan: fixture, relations R01–R05, phases, checks
    ├── claude_plan.md  implementation plan: milestones M0–M5
    └── research.md     claims, limits and sources
```

There is no code yet.
