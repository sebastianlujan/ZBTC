// Circuit tests C1-C12 for Transfer(2,2,20). Requires `pnpm circuit` first.
//
// Every negative test is a single-field mutation of a passing base input:
//   - "raw" mutations change one circuit signal directly;
//   - "semantic" mutations change one transfer field and let buildCircuitInput
//     recompute the derived public values (nf/cm), so that exactly one
//     constraint is violated.
// Each negative test also asserts WHICH constraint failed by matching the
// template and source line that the witness calculator reports.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import * as snarkjs from 'snarkjs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CIRCUITS, DEPTH, PROOF_BYTES, Q, R, REPO_ROOT, type CircuitName } from '../../src/constants.js';
import { cm, keysFromSeed, modR, nf, randomField, skNfOf, type Keys } from '../../src/crypto.js';
import {
  buildCircuitInput,
  bytesToProof,
  dummyInput,
  proofToBytes,
  prove,
  publicSignalsOf,
  shutdownProver,
  verify,
  type CircuitInput,
  type Groth16Proof,
  type PublicSignals,
  type SpendNote,
  type TransferParams,
} from '../../src/prover.js';
import { NoteTree } from '../../src/tree.js';
import { alice, bob } from '../helpers/fixtures.js';

// ---- Locate constraints by source line ----

function sourceLines(rel: string): string[] {
  return readFileSync(path.join(REPO_ROOT, rel), 'utf8').split('\n');
}
const TRANSFER_SRC = sourceLines('circuits/transfer_template.circom');
const MERKLE_SRC = sourceLines('circuits/merkle.circom');

function lineOf(src: string[], snippet: string): number {
  const hits = src.flatMap((l, i) => (l.includes(snippet) ? [i + 1] : []));
  if (hits.length !== 1) throw new Error(`snippet "${snippet}" found ${hits.length} times`);
  return hits[0];
}

const AT = {
  membership: new RegExp(`Transfer_\\d+ line: ${lineOf(TRANSFER_SRC, '(inTree[i].root - root) * inV[i] === 0;')}\\b`),
  nullifier: new RegExp(`Transfer_\\d+ line: ${lineOf(TRANSFER_SRC, 'nf[i] === nfH[i].out;')}\\b`),
  balance: new RegExp(`Transfer_\\d+ line: ${lineOf(TRANSFER_SRC, 'sumIn === sumOut;')}\\b`),
  nfDistinct: new RegExp(`Transfer_\\d+ line: ${lineOf(TRANSFER_SRC, 'nfEq[e].out === 0;')}\\b`),
  outRange: new RegExp(
    `Num2Bits_\\d+ line: \\d+\\s+Error in template Transfer_\\d+ line: ${lineOf(
      TRANSFER_SRC,
      '_ <== Num2Bits(VALUE_BITS)(outV[k]);',
    )}\\b`,
  ),
  posRange: new RegExp(
    `Num2Bits_\\d+ line: \\d+\\s+Error in template MerkleRoot_\\d+ line: ${lineOf(MERKLE_SRC, 'bits.in <== pos;')}\\b`,
  ),
};

async function expectUnsat(input: CircuitInput, at: RegExp, circuit: CircuitName = 'main'): Promise<void> {
  await expect(prove(input, circuit)).rejects.toThrow(/Assert Failed/);
  await expect(prove(input, circuit)).rejects.toThrow(at);
}

// ---- Fixture: a small tree holding notes of Alice and others ----

const mallory: Keys = keysFromSeed(new Uint8Array(32).fill(0x3a));

interface Note {
  v: bigint;
  rseed: bigint;
  pos: number;
}

const tree = new NoteTree();
function mint(v: bigint, owner: bigint): Note {
  const rseed = randomField();
  return { v, rseed, pos: tree.append(cm(v, owner, rseed)) };
}

// Foreign leaves around Alice's notes so positions and paths are non-trivial.
mint(4n, bob.owner);
const noteA = mint(10n, alice.owner);
mint(1n, mallory.owner);
const noteB = mint(6n, alice.owner);
const noteC = mint(6n, alice.owner);
mint(2n, bob.owner);

function spend(n: Note): SpendNote {
  return { v: n.v, rseed: n.rseed, pos: n.pos, path: tree.witness(n.pos) };
}

function out(v: bigint, owner: bigint) {
  return { v, owner, rseed: randomField() };
}

/** 1 real input (A = 10) + 1 dummy -> Bob 7, change 3. */
function baseOneReal(): TransferParams {
  return {
    root: tree.root(),
    hBody: randomField(),
    skSpend: alice.skSpend,
    inputs: [spend(noteA), dummyInput()],
    outputs: [out(7n, bob.owner), out(3n, alice.owner)],
  };
}

/** 2 real inputs of equal value (B = C = 6) -> Bob 9, change 3. */
function baseTwoReal(): TransferParams {
  return {
    root: tree.root(),
    hBody: randomField(),
    skSpend: alice.skSpend,
    inputs: [spend(noteB), spend(noteC)],
    outputs: [out(9n, bob.owner), out(3n, alice.owner)],
  };
}

/** 2 dummy inputs -> two zero-value outputs. */
function baseAllDummy(): TransferParams {
  return {
    root: tree.root(),
    hBody: randomField(),
    skSpend: alice.skSpend,
    inputs: [dummyInput(), dummyInput()],
    outputs: [out(0n, bob.owner), out(0n, alice.owner)],
  };
}

function signalsOf(i: CircuitInput): PublicSignals {
  return publicSignalsOf(i.root, i.hBody, i.nf, i.cm);
}

// Shared valid proof (from C1) for the verifier-side tests C9/C10.
let validProof: Groth16Proof;
let validSignals: PublicSignals;

beforeAll(() => {
  // Sanity: the fixture paths are valid for the current root.
  for (const n of [noteA, noteB, noteC]) {
    expect(NoteTree.verifyPath(tree.leaf(n.pos), n.pos, tree.witness(n.pos))).toBe(tree.root());
  }
});

afterAll(async () => {
  await shutdownProver();
});

describe('Transfer(2,2,20) circuit', () => {
  it('C1a: 1 real + 1 dummy input proves and verifies; signal order and JS values match', async () => {
    const input = buildCircuitInput(baseOneReal());

    const t0 = performance.now();
    const { proof, publicSignals } = await prove(input);
    const proveMs = performance.now() - t0;
    const t1 = performance.now();
    const ok = await verify(publicSignals, proof);
    const verifyMs = performance.now() - t1;
    console.log(`[C1] prove ${proveMs.toFixed(0)} ms, verify ${verifyMs.toFixed(0)} ms`);

    expect(ok).toBe(true);
    // Order: [root, hBody, nf0, nf1, cm0, cm1], identical to publicSignalsOf.
    expect(publicSignals).toEqual(signalsOf(input));
    // Values: the circuit recomputes root/nf/cm and constrains them to these
    // public inputs, so a satisfied witness means JS and circuit agree.
    const skNf = skNfOf(alice.skSpend);
    expect(publicSignals[0]).toBe(tree.root().toString());
    expect(publicSignals[2]).toBe(nf(skNf, noteA.rseed, noteA.pos).toString());
    expect(publicSignals[4]).toBe(input.cm[0].toString());
    expect(input.cm[0]).toBe(cm(7n, bob.owner, input.outRseed[0]));

    validProof = proof;
    validSignals = publicSignals;
  });

  it('C1b: 2 real inputs prove and verify', async () => {
    const input = buildCircuitInput(baseTwoReal());
    const { proof, publicSignals } = await prove(input);
    expect(await verify(publicSignals, proof)).toBe(true);
    expect(publicSignals).toEqual(signalsOf(input));
    const skNf = skNfOf(alice.skSpend);
    expect(publicSignals.slice(2, 4)).toEqual([
      nf(skNf, noteB.rseed, noteB.pos).toString(),
      nf(skNf, noteC.rseed, noteC.pos).toString(),
    ]);
  });

  it('P1: 256-byte proof encoding round-trips to the exact snarkjs JSON and still verifies', async () => {
    const bytes = proofToBytes(validProof);
    expect(bytes).toHaveLength(PROOF_BYTES);
    const back = bytesToProof(bytes);
    expect(back).toEqual(validProof);
    expect(JSON.stringify(back)).toBe(JSON.stringify(validProof));
    expect(await verify(validSignals, back)).toBe(true);

    // Any coordinate >= q is a parse error, never silently reduced.
    const bad = bytes.slice();
    bad.set(new Uint8Array(32).fill(0xff), 0);
    expect(() => bytesToProof(bad)).toThrow(RangeError);
    expect(() => bytesToProof(bytes.subarray(0, PROOF_BYTES - 1))).toThrow(RangeError);
    expect(Q > R).toBe(true);
  });

  it('C2: overflow near r (in [10, 0], out [20, r-10]) fails the 64-bit range check', async () => {
    const p = baseOneReal();
    const input = buildCircuitInput({ ...p, outputs: [out(20n, bob.owner), out(R - 10n, alice.owner)] });
    // Balance holds mod r: 10 + 0 == 20 + (r - 10) (mod r). Only the range check stops it.
    expect(modR(input.inV[0] + input.inV[1] - input.outV[0] - input.outV[1])).toBe(0n);
    await expectUnsat(input, AT.outRange);
  });

  it('C3: the SAME overflow witness verifies on the unsafe norange variant (inflation demo)', async () => {
    const p = baseOneReal();
    const input = buildCircuitInput({ ...p, outputs: [out(20n, bob.owner), out(R - 10n, alice.owner)] });
    const { proof, publicSignals } = await prove(input, 'norange');
    expect(await verify(publicSignals, proof, 'norange')).toBe(true);
    // The production verifier rejects it: different keys.
    expect(await verify(publicSignals, proof, 'main')).toBe(false);
  });

  it('C4: wrong public nf (raw nf[0] + 1) throws', async () => {
    const base = buildCircuitInput(baseOneReal());
    await expectUnsat({ ...base, nf: [modR(base.nf[0] + 1n), base.nf[1]] }, AT.nullifier);
  });

  it('C5: wrong root throws when v > 0 and passes for an all-dummy (v = 0) transfer', async () => {
    const real = buildCircuitInput(baseOneReal());
    await expectUnsat({ ...real, root: randomField() }, AT.membership);

    const dummy = buildCircuitInput(baseAllDummy());
    const { proof, publicSignals } = await prove({ ...dummy, root: randomField() });
    expect(await verify(publicSignals, proof)).toBe(true);
  });

  it('C6: sum mismatch by 1 throws (semantic: out[0].v + 1, cm recomputed)', async () => {
    const p = baseOneReal();
    const o0 = p.outputs[0];
    await expectUnsat(buildCircuitInput({ ...p, outputs: [{ ...o0, v: o0.v + 1n }, p.outputs[1]] }), AT.balance);
  });

  it("C7: spending Alice's note with another sk_spend throws (semantic: skSpend, nf recomputed)", async () => {
    const p = baseOneReal();
    await expectUnsat(buildCircuitInput({ ...p, skSpend: mallory.skSpend }), AT.membership);
  });

  it('C8: the same note in both input slots throws (semantic: inputs[1] = inputs[0])', async () => {
    const p = baseTwoReal();
    const input = buildCircuitInput({ ...p, inputs: [p.inputs[0], p.inputs[0]] });
    expect(input.nf[0]).toBe(input.nf[1]);
    await expectUnsat(input, AT.nfDistinct);
  });

  it('C9: each public signal + 1 makes verify return false', async () => {
    expect(await verify(validSignals, validProof)).toBe(true);
    for (let i = 0; i < validSignals.length; i++) {
      const tweaked = [...validSignals];
      tweaked[i] = modR(BigInt(tweaked[i]) + 1n).toString();
      expect(await verify(tweaked, validProof), `signal ${i}`).toBe(false);
    }
  });

  it('C9b: on nosquare (no hBody constraint) hBody + 1 still makes verify return false', async () => {
    const input = buildCircuitInput(baseOneReal());
    const { proof, publicSignals } = await prove(input, 'nosquare');
    expect(await verify(publicSignals, proof, 'nosquare')).toBe(true);
    const tweaked = [...publicSignals];
    tweaked[1] = modR(BigInt(tweaked[1]) + 1n).toString();
    expect(await verify(tweaked, proof, 'nosquare')).toBe(false);
  });

  it('C10: nf + r as a public signal is rejected (CVE-2023-33252 regression)', async () => {
    const aliased = [...validSignals];
    aliased[2] = (BigInt(aliased[2]) + R).toString();
    expect(modR(BigInt(aliased[2]))).toBe(BigInt(validSignals[2]));
    expect(await verify(aliased, validProof)).toBe(false);
    // snarkjs itself (not only our wrapper) must reject it.
    const vk = JSON.parse(readFileSync(CIRCUITS.main.vkey, 'utf8'));
    expect(await snarkjs.groth16.verify(vk, aliased, validProof)).toBe(false);
    // Wrong arity is rejected too.
    expect(await verify(validSignals.slice(0, 5), validProof)).toBe(false);
  });

  it('C11: constraint count is logged and below 2^15', async () => {
    const info = await snarkjs.r1cs.info(CIRCUITS.main.r1cs);
    console.log(
      `[C11] constraints=${info.nConstraints} wires=${info.nVars} public=${info.nPubInputs} private=${info.nPrvInputs}`,
    );
    expect(info.nPubInputs).toBe(6);
    expect(info.nOutputs).toBe(0);
    expect(info.nConstraints).toBeGreaterThan(0);
    expect(info.nConstraints).toBeLessThan(2 ** 15);
  });

  it('C12: pos >= 2^20 throws (raw, and the aliasing attack with a fresh nf)', async () => {
    const p = baseOneReal();
    const base = buildCircuitInput(p);
    const alias = BigInt(noteA.pos) + (1n << BigInt(DEPTH));

    // Raw: only the position signal changes.
    await expectUnsat({ ...base, inPos: [alias, base.inPos[1]] }, AT.posRange);

    // Semantic: the attacker also recomputes nf for the aliased position,
    // which would be a second, distinct nullifier for the same note.
    const aliased = buildCircuitInput({ ...p, inputs: [{ ...p.inputs[0], pos: alias }, p.inputs[1]] });
    expect(aliased.nf[0]).not.toBe(base.nf[0]);
    await expectUnsat(aliased, AT.posRange);
  });
});
