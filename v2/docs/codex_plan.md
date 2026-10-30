# Plan: ZBTC v2 — toy note → AADP → native regtest spend

A functional toy note-to-AADP-to-Bitcoin demonstration.

Date: 2026-10-30. Status: **planned**. Runtime validation: **not run**.

Show one complete functional path: a known toy note at a frozen snapshot supplies the witness for actual AADP decryption; the recovered secret unlocks a Bitcoin key, and that key spends one native regtest UTXO. Reconstruct missing code from the paper. Deliberately weak relations, tiny secrets and an honest setup are acceptable. Security hardening is not a prerequisite or an objective of this demo.

**Current authorization:** Research and planning documents only (this plan and [research.md](research.md)). No cryptographic execution, installation, or PoC implementation.

**Revision note:** Scope corrected to functional education only. Required path includes the direct toy-note relation and confirmed native spend. Security research is deferred. Only planning documents changed; no cryptographic execution or implementation.

## Functional acceptance

- Use one declared note and one fixed local snapshot, with the setup operator knowing all fixture secrets.
- Generate an assignment for the explicit note-opening, owner-tag, nullifier-tag and amount equations, then use that assignment in actual AADP matrix decryption.
- Recover the expected field element mu, derive the envelope key with HKDF, and authenticate/decrypt the actual Bitcoin private-key bytes; no mocked decrypt or host-language authorization shortcut.
- Sign with the recovered key, have Bitcoin Core accept and mine the transaction, and check the serialized transaction ID, spent outpoint and expected recipient output.
- Record selected alternate-witness results as functional examples only; no universal rejection, soundness, privacy or security claim is required.

## Required path

Follow **P00 → P01 → P03 → P04 → P02**. R01 is only a plumbing checkpoint; P03/P04 are required before claiming a note-driven spend. P05/P06/P07 are deferred and do not gate completion.

Optional paths, all deferred:

- **P05**: a full SNARK/Groth16 adapter; unnecessary for the direct toy-note relation.
- **P06**: fixed-signature release; the core demo deliberately releases the raw Bitcoin key.
- **P07**: the independent Circom note-proof baseline.

## Explicit assumptions and non-goals

- **A01**: Local files and Bitcoin regtest only: no bridge, wrapped asset, other chain, federation, or external authorizer.
- **A02**: One fresh, isolated UTXO; one known genesis fixture; fixed denomination; no pooled key or concurrent note transfers.
- **A03**: An honest setup operator knows the Bitcoin key and all fixture secrets. No erasure, MPC/DKG or setup-correctness proof is needed for the demonstration.
- **A04**: Short secrets, deliberately weak algebraic commitments, reduced-round hashes or smaller fields are permitted. The selected field must represent the fixture amounts, or use explicit integer encoding. No cryptographic-strength target is imposed.
- **A05**: One note is issued directly in a declared fixture at a selected regtest snapshot. No Merkle tree, replay service, current-state proof, concurrent transfers or revocation mechanism is required.
- **A06**: Amounts, transaction graph, and fees remain visible on Bitcoin. One note gives no meaningful anonymity set; off-chain ciphertext alone does not change that.

**Non-goals:**

- Security readiness, secure hash parameters, attack resistance, adaptive WE security, production deployment or a full shielded pool.
- MPC/DKG, OutVerify/setup proofs, key erasure, security patches or adversarial security testing as prerequisites.
- A full Groth16/SNARK adapter, authenticated dynamic state, freshness, reorg handling, repeated withdrawals or vault reuse.
- A frontend, general framework, bridge, new chain, BitVM or Silent Payments integration.

## Core flow

1. Issue the single toy note R04 and fund its associated 101000-sat regtest UTXO. Freeze the fixture; keep the setup operator explicitly trusted.
2. Emit R04 coefficient rows and its opening assignment. Run Algorithm 1 for that relation, then encrypt a field element mu using Algorithm 2.
3. Derive K with HKDF from a canonical fixed-width encoding of mu; AEAD-encrypt the complete Bitcoin key bytes. Keep ciphertext and envelope in local files.
4. Use the note-opening assignment in Algorithm 3 to recover mu; derive K and decrypt the key. The recipient flow must consume the recovered value rather than a setup copy.
5. Build and sign the ordinary regtest spend, sending 100000 sats to the fixture recipient with a 1000-sat fee; submit and mine it, then record the checks below.

## Reconstruct missing pieces from the paper

Reconstruct the published matrix algorithms; use R01 only as a conformance checkpoint and R04 as the required deliberately insecure note relation. All derivations and experiments remain planned, not executed.

The original equations and the deliberately uncertified R04 relation are used only for a functional educational example. Published attacks and proposed patches remain background. Security hardening, projective certification, MPC and setup proofs are deferred and do not gate this demo. [S12](https://www.allocinit.xyz/uploads/aadp-attacks.pdf) [S13](https://www.allocinit.xyz/posts/commutator-attack) [S05](https://insider.btcpp.dev/p/shielded-bitcoin-and-pipes-facts)

**R01 — A fully explicit homogeneous relation** (hand-derived conformance vector). BN254 base field q=21888242871839275222246405745257275088696311157297823662689037894645226208583; distinct from the official toy scalar field.

```text
variables: ('x0', 'x', 'x2', 'x3'); witness: (1, 2, 4, 8); c_star=32
x*x=x0*x2
x0*x3=x2*x
c_star*x0*x0=x2*x3
x2*x2=x*x3
x3*x3=c_star*x*x0
(A,B,C,D): (e1,e1,e0,e2); (e0,e3,e2,e1); (c_star*e0,e0,e2,e3); (e2,e2,e1,e3); (e3,e3,c_star*e0,e1)
```

Order x before x2 before x3: rows 1, 4, 5 certify them. At x0=0 those rows force all other coordinates to zero. Gadget 12 with its output fixed to c_star. It is only an algebraic conformance vector: x^5 is efficiently invertible in this field, so this is neither a hard witness relation nor a note commitment. [S03](https://www.allocinit.xyz/uploads/aadp.pdf)

**R02 — Generate coefficient matrices** (paper algorithm). For each constraint i, form linear a_i,b_i,c_i,d_i and random xi_i. U_i=[[a_i,c_i,-xi_i,0],[d_i,b_i,0,xi_i],[0,0,b_i,c_i],[0,0,d_i,a_i]]. Sample L_i in F^(k*4), R_i in F^(4*k), k=2m+1; M_j=sum_i L_i*U_i^(j)*R_i.

Recreate Algorithm 1 directly with arbitrary coefficient rows and a trace generator. The challenge-specific normalization is not a required step of Algorithm 1. [S03](https://www.allocinit.xyz/uploads/aadp.pdf) [S01](https://github.com/alloc-init/aadp-cryptographic-challenges/blob/master/code/aadp_construction.sage)

**R03 — Encrypt and recover the envelope secret** (paper algorithm and derived simplification). Delta has a single 1 at (k-1,k-1). Mhat_0=M_0+mu*Delta; other Mhat_j=M_j. E=sum_j w_j*Mhat_j. Solve det(E-t*Delta)=0. Equivalently t=det(E)/det(E[0:k-1,0:k-1]) when the denominator is nonzero.

Recreate Algorithms 2-3, retain only ciphertext for the recipient, and handle a zero denominator as an explicit fixture failure. Authenticate the recovered candidate with the expected mu or AEAD tag. [S03](https://www.allocinit.xyz/uploads/aadp.pdf)

**R04 — The required minimal toy-note relation** (proposed engineering relation). Use the R01 field and local toy format: owner_tag=k_owner^2; C_note=a+owner_tag+rho; N=k_owner*rho; a=a_exit. Fix owner_tag=9, C_note=100014, N=15 and a_exit=100000. Set w=(x0,k_owner,rho,a)=(1,3,5,100000). The four homogeneous equations below encode this exact opening/owner/value fixture.

```text
k_owner*k_owner=owner_tag*x0*x0
(a+rho+(owner_tag-C_note)*x0)*x0=0
k_owner*rho=N*x0*x0
a*x0=a_exit*x0*x0
(A,B,C,D): (e1,e1,owner_tag*e0,e0); (e3+e2+(owner_tag-C_note)*e0,e0,0,0); (e1,e2,N*e0,e0); (e3,e0,a_exit*e0,e0)
expected rows: 9=9, 0=0, 15=15, 100000=100000
```

This is an intentionally weak algebraic note commitment and nullifier tag, not a secure hash or the Shielded Bitcoin wire format. Other openings may exist; known secrets and one public note provide no anonymity. The relation is not projectively safe: at x0=0, a and rho need not vanish. We reuse Algorithm 1 and check selected valid-witness recovery, without claiming the paper security theorem. Snapshot/outpoint/recipient stay external fixture metadata; raw-key release allows other spends. [S09](https://www.allocinit.xyz/posts/Shielded-Bitcoin-paper) [S04](https://www.allocinit.xyz/uploads/pipesv2.pdf)

**R05 — Deferred hash-shaped relation** (paper gadgets with engineering composition). Gadget 12: x^2=x0*x2; x0*x3=x2*x; x0*x5=x2*x3; x2^2=x*x3; x3^2=x*x5. Compute x2,x3,x5 by field arithmetic as witness hints, and separately enforce all five equations. Compose Gadget 13 rounds and linear layers, recording variable order and certificates.

Optional later extension only. A reduced-round hash is acceptable if explicitly weak; full Poseidon parameters and projective certification are unnecessary for R04. For a faithful certified paper construction, final/dropped state words need certificates, and field, rounds, constants, MDS and encoding must match. Circom scalar-field parameters do not transfer unchanged to the base field. [S03](https://www.allocinit.xyz/uploads/aadp.pdf) [S07](https://github.com/alloc-init/crypto-research-aadp-estimates/blob/master/main.py)

**Size forecast.** (n+1)*(2m+1)^2*32 bytes for dense matrices; public parameters, framing and AEAD are additional.

- R01 conformance vector: n=3, m=5, **15,488 bytes**.
- R04 deliberately uncertified toy note: n=3, m=4, **10,368 bytes**.
- Hypothetical sensitivity case, not a hash estimate: n=100, m=100, **130,576,032 bytes**.
- Hypothetical sensitivity case, not a hash estimate: n=1000, m=1000, **128,256,160,032 bytes**.

Forecast before allocation; 256 MiB is an initial practical ceiling, not a security requirement. R04 forecasts 10368 bytes of dense 32-byte field entries, excluding framing and the envelope; runtime and exact serialization remain unmeasured.

**Planned checks:**

- R01 expected row values: 4=4, 8=8, 32=32, 16=16, 64=64. R04 expected row values: 9=9, 0=0, 15=15, 100000=100000. These are hand-derived expectations, not executed tests.
- For the selected deterministic fixture, compare emitted rows and assignments, record the recovery cofactor, then compare recovered mu and key bytes with expected values.
- A selected wrong assignment can produce any candidate t, including an accidental recovery. Record equality/AEAD results without asserting universal failure or soundness.
- Context is authenticated only by the envelope convention and selected transaction unless explicitly constrained. R04 alone does not check Bitcoin state or recipient.
- Confirm the real regtest transaction using the planned-interface txid, amount, fee and spent-outpoint checks. Projective certificates and adversarial attack tests are not demo acceptance criteria.

**Remaining implementation choices:** Recorded setup seed with a nonzero recovery cofactor; Canonical field/matrix/key encodings and AEAD associated data; Pinned Sage/Bitcoin Core versions and explicit Bitcoin key/tweak convention.

**Functional stop conditions:**

- Incorrect coefficients or assignment prevent the selected valid witness from recovering the expected mu/key.
- The actual matrix/AEAD path is replaced by mocked decryption or a host-language verify-then-release shortcut.
- The local artifact cannot fit the declared resource budget.
- No correctly valued native regtest transaction is confirmed using the recovered key.

## One-note fixture contract

R04 constrains only its stated note equations. Snapshot, outpoint and recipient are chosen fixture metadata. AEAD authenticates that metadata but does not make it an AADP predicate or restrict a released key.

- w_exit: the actual note-opening assignment consumed by AADP decryption; this is the core demo input.
- pi_note: a separate public ZK note proof, deferred; the core uses no Groth16 proof.
- pi_setup: a setup-correctness proof, deferred; the core trusts its setup operator.

**Public constants/metadata:** relation and field identity; owner_tag=9, C_note=100014, N=15, amount_sats=100000; selected regtest snapshot and funding outpoint as fixture metadata; recipient script, recipient_amount_sats=100000 and fee_sats=1000 as fixture metadata.

**Witness/setup inputs:** k_owner=3 and rho=5; known educational fixture secrets; w_exit=(x0,k_owner,rho,a)=(1,3,5,100000); Bitcoin signing key and mu known to setup, but recovered through the ciphertext/envelope in the recipient flow.

- The generated witness satisfies all four R04 coefficient rows, including the fixed note amount; note_amount_sats=recipient_amount_sats=100000 and funding_amount_sats=101000=recipient_amount_sats+fee_sats.
- The matrix decrypt path recovers the original mu for the selected valid fixture, with a nonzero recovery cofactor; the AEAD envelope yields the original Bitcoin key bytes.
- The resulting native transaction spends the fixture outpoint and is confirmed by regtest Core with the specified output and fee. Local note accounting alone is insufficient.
- A local consumed marker is a transcript convenience only. Old witnesses, alternate spends and public witness copying are acknowledged but need no prevention mechanism in this one-shot experiment.

## Planned minimal interface

These are proposed calls and files, not implemented artifacts.

```text
prepare(fixture) -> coefficients, ciphertext, envelope, witness
unlock(ciphertext, envelope, witness) -> recovered_btc_key
spend(fixture, recovered_btc_key) -> raw_transaction, result
```

- `fixture.json`: Field/relation identity, fixed note constants, known test secrets, Bitcoin key/address convention, selected snapshot, funding outpoint, recipient and amounts. Secrets may be present because this is an explicit test fixture.
- `ciphertext + envelope.json`: Actual encrypted matrices and AEAD envelope, with field/byte encoding and associated-data convention. The recipient flow must not read mu or original matrices from setup.
- `witness.json`: The generated R04 assignment in canonical coordinate order.
- `result.json`: Recovered-secret equality checks, cofactor status, raw spend transaction, locally computed txid, Core-returned txid, confirmation and expected value/outpoint checks.

**Expected results:**

- For the selected note, expect owner_tag=9, C_note=100014, N=15, note/output amount=100000 sats, funding amount=101000 sats and fee=1000 sats.
- Compute expected_txid from the exact serialized signed transaction, then require Core returned txid and the mined transaction txid to match; do not invent a txid in this plan.
- After mining, getrawtransaction reports at least one confirmation and the designated recipient output has value 100000 sats; gettxout returns null for the spent funding outpoint and the expected value for the recipient output. If a dedicated initially empty recipient wallet is used, its new balance is 100000 sats.
- Seeds/fixtures may make local algebra deterministic. Cross-run transaction IDs are equal only if funding outpoints and all transaction bytes are also identical; no cross-run block-timestamp assumption is required.
- For a selected changed witness, record candidate mu and AEAD outcome. A mismatch is illustrative; accidental recovery or another valid opening is permitted by the deliberately insecure relation.

## Planned phases

### P00 — Freeze the experiment

**core**; depends on: none. Make the smallest claim reproducible before implementing anything.

- [ ] Record the AADP source, Sage and Bitcoin Core versions, selected field and deliberately insecure fixture values.
- [ ] Fix one note, funding outpoint, recipient, amount and fee; use the small artifact interface below with an explicitly honest setup.

**Deliverable:** D00 — Source/environment manifest and public/private artifact inventory.

**Success:** The fixture is concrete enough to reproduce; its known secrets and frozen-snapshot assumption are explicit.

**Failure:** The fixture omits the note relation, amounts, key/address convention or data needed to reproduce its spend.

**Sources:** [S01](https://github.com/alloc-init/aadp-cryptographic-challenges/blob/master/code/aadp_construction.sage) [S02](https://github.com/alloc-init/aadp-cryptographic-challenges/blob/master/code/aadp_challenge_writer.sage)

### P01 — Recover a local envelope secret

**core**; depends on: P00. Exercise real AADP decryption without a note system or Bitcoin integration.

- [ ] Reuse the official small construction or reconstruct R01-R03 to check matrix/envelope plumbing; this checkpoint alone is not the note demo.
- [ ] Check expected-mu recovery and HKDF/AEAD recovery of complete key bytes; do not reduce a Bitcoin scalar modulo the AADP field.
- [ ] Record one selected alternate-witness/envelope result without requiring all wrong witnesses to fail or treating sample results as a security test.

**Deliverable:** D01 — Expected-value matrix/envelope transcript for the selected conformance fixture.

**Success:** The decrypt path uses ciphertext and the intended assignment to recover the expected mu and key bytes, rather than reading their setup copies.

**Failure:** Recovery relies on a server decision, a leaked setup value, or a mocked decrypt function.

**Sources:** [S01](https://github.com/alloc-init/aadp-cryptographic-challenges/blob/master/code/aadp_construction.sage) [S02](https://github.com/alloc-init/aadp-cryptographic-challenges/blob/master/code/aadp_challenge_writer.sage)

### P03 — Fix one educational note

**core**; depends on: P00. Define a minimal amount/owner/opening relation tied to the one local funding fixture.

- [ ] Use R04 exactly: amount=100000, k_owner=3, rho=5, owner_tag=9, C_note=100014 and N=15; declare this algebraic commitment deliberately weak.
- [ ] Freeze one selected regtest snapshot and associate this issued note with one UTXO. Treat snapshot/outpoint/recipient as chosen metadata, not dynamically checked AADP state.
- [ ] Specify the four witness coordinates, fixed note/output amount and 101000=100000+1000 funding/output/fee split; keep every Bitcoin key byte separate from field-element encoding.

**Deliverable:** D03 — One concrete note/funding fixture and its four-row coefficient/witness specification.

**Success:** The fixture checks its selected opening, owner tag and amount; it is a note model rather than an unrelated square puzzle.

**Failure:** The proposed note checks exist only in prose or a host-language if statement and are absent from the relation sent to Algorithm 1.

**Sources:** [S04](https://www.allocinit.xyz/uploads/pipesv2.pdf) [S09](https://www.allocinit.xyz/posts/Shielded-Bitcoin-paper)

### P04 — Decrypt from the toy note witness

**core**; depends on: P01, P03. Connect the four-row note relation to actual AADP matrix generation, encryption and recovery.

- [ ] Reconstruct the Eq. (1) row emitter and Algorithms 1-3 if needed; emit R04 rows and its deterministic assignment without challenge-specific normalization.
- [ ] Check the row equalities, construct the ciphertext and recover mu with the note assignment; feed that recovered mu into the actual HKDF/AEAD key envelope.
- [ ] Record the selected cofactor and recovered-secret checks. If a sampled setup has zero cofactor, report it and choose another recorded setup; investigate the algebra if no valid fixture recovers.
- [ ] Keep the relation deliberately uncertified and weak; record that departure from the paper security class. Projective-safety certification, full Poseidon, patches and adversarial tests are not prerequisites.

**Deliverable:** D04 — Functional note-assignment -> ciphertext -> recovered mu/key transcript and measured artifact sizes when implemented.

**Success:** Actual matrix decryption for the selected note opening yields the envelope secret and original key bytes, without a host verify-then-release substitute.

**Failure:** Incorrect coefficients/assignment, failure to recover the expected secret, mocked decryption, or an artifact too large for the declared local budget prevents the functional path.

**Sources:** [S01](https://github.com/alloc-init/aadp-cryptographic-challenges/blob/master/code/aadp_construction.sage) [S03](https://www.allocinit.xyz/uploads/aadp.pdf)

### P02 — Spend one native regtest UTXO

**core**; depends on: P04. Connect the recovered key to an ordinary Bitcoin transaction.

- [ ] Use one dedicated regtest key/address fixture with explicit Taproot key/tweak handling.
- [ ] Build and sign with the key recovered from the R04 note witness; submit and mine the transaction with 100000 sats to the recipient and a 1000-sat fee.
- [ ] Record the expected txid computed from raw transaction bytes, compare it with Core, and use getrawtransaction to check confirmation and recipient value, and gettxout to check the spent funding outpoint and unspent recipient output.

**Deliverable:** D02 — Funding/spend transaction identifiers and a short demonstration transcript.

**Success:** The complete note-assignment -> AADP -> AEAD -> recovered key -> confirmed native regtest spend path has the specified transaction/value results.

**Failure:** The transaction is rejected or unconfirmed, values/outpoints do not match, or a setup copy/signing service replaces the recovered key.

**Sources:** [S04](https://www.allocinit.xyz/uploads/pipesv2.pdf) [S10](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)

### P05 — Reconstruct a proof-system adapter if needed

**deferred**; depends on: P03. Recreate missing proof-system components from their equations rather than waiting for a compiler repository.

- [ ] Only if separately requested later, reconstruct the tailored SNARK or a complete Groth16 verifier from the paper, including its witness generator and parameter choices.
- [ ] Treat stronger cryptography, setup proofs, state freshness and attack/patch evaluation as separate research; none is needed for P00-P04.

**Deliverable:** D05 — From-paper prover/verifier/adapter specification, reference vectors, unresolved assumptions, and conditional cost budget.

**Success:** A separately requested adapter has explicit equations and cost estimates; its absence does not delay the core demo.

**Failure:** snarkjs.verify() followed by ordinary decryption is called PIPE enforcement, or 'BN254 compatible' is used as a substitute for a verifier.

**Sources:** [S03](https://www.allocinit.xyz/uploads/aadp.pdf) [S05](https://insider.btcpp.dev/p/shielded-bitcoin-and-pipes-facts) [S06](https://github.com/iden3/snarkjs/blob/master/src/groth16_verify.js) [S07](https://github.com/alloc-init/crypto-research-aadp-estimates/blob/master/main.py) [S12](https://www.allocinit.xyz/uploads/aadp-attacks.pdf) [S13](https://www.allocinit.xyz/posts/commutator-attack)

### P06 — Optionally release one transaction signature

**deferred**; depends on: P02. Demonstrate transaction binding without delivering the unrestricted Bitcoin key.

- [ ] Encrypt a precomputed Schnorr signature for one exact SIGHASH_DEFAULT withdrawal transaction instead of btc_sk; fix recipient, amount, fee, inputs, and locktime.
- [ ] Test that altered outputs invalidate the signature, while copying the unlocked signature only permits the same transaction. Keep the setup-key bypass visible.

**Deliverable:** D06 — Comparison transcript: key release versus fixed-signature release.

**Success:** The recipient cannot redirect the fixed signature; the experiment is labeled an engineering variation with trusted setup.

**Failure:** The variation is described as a dynamic vault, general PIPE, or proof that the setup signer erased its key.

**Sources:** [S10](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) [S04](https://www.allocinit.xyz/uploads/pipesv2.pdf)

### P07 — Optionally reuse the existing note-proof baseline

**deferred**; depends on: P00. Study note privacy and replay independently of AADP.

- [ ] Use the pinned two-input/two-output scenario rather than redesigning its circuit; separate real proving tests from mocked replay tests.
- [ ] Use a declared synthetic genesis and no demo-vault custody. Keep proof/public-input/ciphertext data available together; a digest without retrievable data is insufficient.

**Deliverable:** D07 — Independent proof/replay transcript with no claim of native redemption.

**Success:** The baseline illustrates note validation and replay without being presented as the AADP adapter.

**Failure:** Mock acceptance or the repository's vault is presented as completed cryptographic Bitcoin enforcement.

**Sources:** [S08](https://github.com/harshjv/shielded-bitcoin-poc/tree/0a715f1efba73821d717ac37f39d95aa76dda995) [S09](https://www.allocinit.xyz/posts/Shielded-Bitcoin-paper)

## Deferred concerns

Deferred concerns for stronger claims only; none blocks the functional demo.

- **B01 — Unverified cryptographic integration:** Security revisions, patches and resistance to known attacks are outside this functional demonstration.
- **B02 — Setup authority remains:** Keep the honest setup assumption. MPC/DKG, OutVerify and erasure are deferred.
- **B03 — Dynamic state and stale witnesses:** Keep the single frozen fixture; dynamic history, freshness, revocation and reorg handling are deferred.
- **B04 — Release is not transaction restriction:** Release the raw key for simplicity. It can sign other spends; restricted-capability release is deferred to P06.

## Evidence and sources

Background claims C01–C13, the source register S01–S13 (locators, revisions, verification methods and dates) and the conclusion drawn from them are in [research.md](research.md). The inline [Sxx] links in this plan point to the same sources.
