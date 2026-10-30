// Groth16 malleability: a re-randomized proof verifies for the same public
// signals but has different bytes. This is why duplicates are detected only
// by nullifier (plan, "Duplicates are detected only by nullifier").
import { readFileSync } from 'node:fs';
import { afterAll, describe, expect, it } from 'vitest';
import { parse } from '../../src/codec.js';
import { CIRCUITS } from '../../src/constants.js';
import { bytesToHex, cm, randomField } from '../../src/crypto.js';
import { bytesToProof, dummyInput, proofToBytes, shutdownProver, verify, type VerificationKey } from '../../src/prover.js';
import { NoteTree } from '../../src/tree.js';
import { craftTransfer, withProofBytes } from '../helpers/craft.js';
import { rerandomize } from '../helpers/rerandomize.js';
import { alice, bob } from '../helpers/fixtures.js';

const vk = JSON.parse(readFileSync(CIRCUITS.main.vkey, 'utf8')) as VerificationKey;

afterAll(async () => {
  await shutdownProver();
});

describe('Groth16 re-randomization', () => {
  it('verifies under snarkjs for the same public signals, with different bytes', async () => {
    const tree = new NoteTree();
    const rseed = randomField();
    tree.append(cm(50n, alice.owner, rseed));
    const t = await craftTransfer({
      root: tree.root(),
      hAnchor: 7,
      skSpend: alice.skSpend,
      inputs: [{ v: 50n, rseed, pos: 0, path: tree.witness(0) }, dummyInput()],
      outputs: [
        { v: 20n, owner: bob.owner, pkEnc: bob.pkEnc },
        { v: 30n, owner: alice.owner, pkEnc: alice.pkEnc },
      ],
    });
    expect(await verify(t.publicSignals, t.proof)).toBe(true);

    const p1 = rerandomize(t.proof, vk);
    const p2 = rerandomize(t.proof, vk);
    expect(await verify(t.publicSignals, p1)).toBe(true);
    expect(await verify(t.publicSignals, p2)).toBe(true);

    const b0 = bytesToHex(proofToBytes(t.proof));
    const b1 = bytesToHex(proofToBytes(p1));
    const b2 = bytesToHex(proofToBytes(p2));
    expect(new Set([b0, b1, b2]).size).toBe(3);
    // Every one of the 8 coordinates changed.
    for (let i = 0; i < 8; i++) expect(b1.slice(64 * i, 64 * i + 64)).not.toBe(b0.slice(64 * i, 64 * i + 64));

    // Same body, new proof: still a canonical envelope (points in the subgroup)
    // and the round-tripped bytes still verify.
    const copy = withProofBytes(t.bytes, proofToBytes(p1));
    const parsed = parse(copy);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(await verify(t.publicSignals, bytesToProof(parsed.env.proofBytes))).toBe(true);
    expect(bytesToHex(copy.subarray(0, 316))).toBe(bytesToHex(t.bytes.subarray(0, 316)));

    // It does not transfer to other public signals.
    const other = [...t.publicSignals];
    other[1] = (BigInt(other[1]) + 1n).toString();
    expect(await verify(other, p1)).toBe(false);
  });
});
