// Groth16 malleability: a re-randomized proof verifies for the same public
// signals but has different bytes. This is why duplicates are detected only
// by nullifier (plan, "Duplicates are detected only by nullifier").
import { afterAll, describe, expect, it } from 'vitest';
import { parse } from '../../src/codec.js';
import { bytesToHex } from '../../src/crypto.js';
import { bytesToProof, loadVkey, proofToBytes, shutdownProver, verify } from '../../src/prover.js';
import { craftAliceToBob, withProofBytes } from '../helpers/craft.js';
import { rerandomize } from '../helpers/rerandomize.js';

const vk = loadVkey();

afterAll(async () => {
  await shutdownProver();
});

describe('Groth16 re-randomization', () => {
  it('verifies under snarkjs for the same public signals, with different bytes', async () => {
    const t = await craftAliceToBob({ v: 50n, pay: 20n, hAnchor: 7 });
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
