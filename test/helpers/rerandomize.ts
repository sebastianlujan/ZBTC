// Groth16 proof re-randomization with noble bn254 (public, needs no witness):
//   A' = r^-1 * A,   B' = r * B + r*s * delta2,   C' = C + s * A
// e(A',B') = e(A,B) * e(s*A, delta2) and e(C',delta2) = e(C,delta2) * e(s*A, delta2),
// so the verification equation still holds for the same public signals while
// every proof byte changes. Groth16 proofs are malleable in this way; ZBTC
// therefore detects duplicates only by nullifier, never by proof bytes.
import { bn254 } from '@noble/curves/bn254.js';
import type { Groth16Proof, VerificationKey } from '../../src/prover.js';
import { randomField } from '../../src/crypto.js';

const { G1, G2 } = bn254;
const Fr = bn254.fields.Fr;

type G2Json = [[string, string], [string, string], [string, string]] | string[][];

function g1(a: readonly string[]) {
  return G1.Point.fromAffine({ x: BigInt(a[0]), y: BigInt(a[1]) });
}

function g2(b: G2Json) {
  return G2.Point.fromAffine({
    x: { c0: BigInt(b[0][0]), c1: BigInt(b[0][1]) },
    y: { c0: BigInt(b[1][0]), c1: BigInt(b[1][1]) },
  });
}

function nonZeroScalar(): bigint {
  for (;;) {
    const x = Fr.create(randomField());
    if (x !== 0n) return x;
  }
}

export function rerandomize(proof: Groth16Proof, vk: VerificationKey, r = nonZeroScalar(), s = nonZeroScalar()): Groth16Proof {
  const A = g1(proof.pi_a);
  const B = g2(proof.pi_b);
  const C = g1(proof.pi_c);
  const delta2 = g2(vk.vk_delta_2 as G2Json);

  const A2 = A.multiply(Fr.inv(r)).toAffine();
  const B2 = B.multiply(r).add(delta2.multiply(Fr.mul(r, s))).toAffine();
  const C2 = C.add(A.multiply(s)).toAffine();

  const d = (x: bigint) => x.toString(10);
  return {
    pi_a: [d(A2.x), d(A2.y), '1'],
    pi_b: [
      [d(B2.x.c0), d(B2.x.c1)],
      [d(B2.y.c0), d(B2.y.c1)],
      ['1', '0'],
    ],
    pi_c: [d(C2.x), d(C2.y), '1'],
    protocol: 'groth16',
    curve: 'bn128',
  };
}
