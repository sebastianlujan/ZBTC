// F_q arithmetic, determinants on small hand-checked matrices, and the
// determinism of the seeded setup sampler.
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { BASE_FIELD_MODULUS, FIELD_ELEMENT_BYTES } from '../../src/constants.js';
import {
  determinant,
  encodeFieldElement,
  inverse,
  leadingMinor,
  matrixMultiply,
  mod,
  mul,
  seededSampler,
  type Sampler,
} from '../../src/field.js';

/** BN254 scalar field r: Codex's prototype used it by mistake; q must not reduce it to zero. */
const SCALAR_FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SEED = utf8ToBytes('zbtc/v2/test/field-seed');
const OTHER_SEED = utf8ToBytes('zbtc/v2/test/other-seed');
const TAG = 'zbtc/v2/test/tag';
const OTHER_TAG = 'zbtc/v2/test/other-tag';
const SAMPLE_COUNT = 16;

function take(sample: Sampler, count = SAMPLE_COUNT): bigint[] {
  return Array.from({ length: count }, () => sample());
}

describe('scalars', () => {
  it('works over the BN254 base field q, not the scalar field r', () => {
    expect(mod(BASE_FIELD_MODULUS)).toBe(0n);
    expect(mod(SCALAR_FIELD_MODULUS)).not.toBe(0n);
  });

  it('reduces negative values into [0, q)', () => {
    expect(mod(-1n)).toBe(BASE_FIELD_MODULUS - 1n);
  });

  it('inverts every nonzero element it is given', () => {
    for (const value of [1n, 2n, 7n, 123_456_789n, BASE_FIELD_MODULUS - 1n, -5n]) {
      expect(mul(mod(value), inverse(value))).toBe(1n);
    }
    expect(inverse(BASE_FIELD_MODULUS - 1n)).toBe(BASE_FIELD_MODULUS - 1n);
  });

  it('refuses to invert zero, in any representation', () => {
    expect(() => inverse(0n)).toThrow(RangeError);
    expect(() => inverse(BASE_FIELD_MODULUS)).toThrow(RangeError);
  });

  it('encodes field elements at a fixed width, leading zeros included', () => {
    const one = encodeFieldElement(1n);
    expect(one).toHaveLength(FIELD_ELEMENT_BYTES);
    expect(one[0]).toBe(0);
    expect(one[FIELD_ELEMENT_BYTES - 1]).toBe(1);
    expect(() => encodeFieldElement(BASE_FIELD_MODULUS)).toThrow(RangeError);
    expect(() => encodeFieldElement(-1n)).toThrow(RangeError);
  });
});

describe('matrices', () => {
  it('multiplies conformable matrices', () => {
    const product = matrixMultiply(
      [
        [1n, 2n],
        [3n, 4n],
      ],
      [
        [5n, 6n],
        [7n, 8n],
      ],
    );
    expect(product).toEqual([
      [19n, 22n],
      [43n, 50n],
    ]);
    expect(() => matrixMultiply([[1n, 2n]], [[1n, 2n]])).toThrow(RangeError);
  });

  it('computes determinants of small known matrices, with and without row swaps', () => {
    expect(determinant([[3n]])).toBe(3n);
    expect(determinant([[1n, 2n], [3n, 4n]])).toBe(mod(-2n));
    expect(determinant([[0n, 2n], [3n, 4n]])).toBe(mod(-6n));
    expect(determinant([[6n, 1n, 1n], [4n, -2n, 5n], [2n, 8n, 7n]])).toBe(mod(-306n));
    expect(determinant([[0n, 0n, 1n], [0n, 1n, 0n], [1n, 0n, 0n]])).toBe(mod(-1n));
  });

  it('returns 0 for singular matrices', () => {
    expect(determinant([[2n, 4n], [1n, 2n]])).toBe(0n);
    expect(determinant([[1n, 2n, 3n], [4n, 5n, 6n], [7n, 8n, 9n]])).toBe(0n);
    expect(determinant([[0n, 1n], [0n, 5n]])).toBe(0n);
  });

  it('rejects a non-square determinant', () => {
    expect(() => determinant([[1n, 2n]])).toThrow(RangeError);
  });

  it('takes the leading minor by dropping the last row and column', () => {
    const matrix = [
      [1n, 2n, 3n],
      [4n, 5n, 6n],
      [7n, 8n, 9n],
    ];
    expect(leadingMinor(matrix)).toEqual([
      [1n, 2n],
      [4n, 5n],
    ]);
  });
});

describe('seeded sampler', () => {
  it('replays the same sequence for the same seed and tag', () => {
    expect(take(seededSampler(SEED, TAG))).toEqual(take(seededSampler(SEED, TAG)));
  });

  it('separates sequences by tag and by seed', () => {
    const reference = take(seededSampler(SEED, TAG));
    expect(take(seededSampler(SEED, OTHER_TAG))).not.toEqual(reference);
    expect(take(seededSampler(OTHER_SEED, TAG))).not.toEqual(reference);
  });

  it('only yields canonical field elements', () => {
    for (const value of take(seededSampler(SEED, TAG), SAMPLE_COUNT * 8)) {
      expect(value >= 0n && value < BASE_FIELD_MODULUS).toBe(true);
    }
  });
});
