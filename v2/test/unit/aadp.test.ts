// AADP Algorithms 1–3 on the R01 conformance vector (docs/codex_plan.md):
// Gadget 12 with its output fixed to c_star = 32, over variables
// (x0, x, x2, x3) with witness (1, 2, 4, 8). m = 5, so k = 11.
//
// Every setup here comes from a fixed seed, so each assertion is about one
// reproducible ciphertext, not about AADP in general.
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import {
  ciphertextBytes,
  decrypt,
  encrypt,
  evaluateMatrices,
  recoveryCofactor,
  ZeroCofactorError,
} from '../../src/aadp.js';
import { AADP_SETUP_DOMAIN, BASE_FIELD_MODULUS } from '../../src/constants.js';
import { determinant, mod, seededSampler, zeroMatrix } from '../../src/field.js';
import {
  constraintSides,
  satisfies,
  unitForm,
  type Constraint,
  type LinearForm,
} from '../../src/relation.js';

// ---- R01 fixture ----

/** (x0, x, x2, x3) */
const VARIABLES = 4;
const C_STAR = 32n;
const WITNESS = [1n, 2n, 4n, 8n];
/** x3 changed from 8 to 9: breaks rows 2, 4 and 5. */
const CHANGED_WITNESS = [1n, 2n, 4n, 9n];
const EXPECTED_ROW_VALUES = [4n, 8n, 32n, 16n, 64n];
/** (n+1)·k²·32 = 4 · 11² · 32. */
const R01_CIPHERTEXT_BYTES = 15_488;

const SETUP_SEED = utf8ToBytes('zbtc/v2/test/r01-setup-seed');
const OTHER_SEED = utf8ToBytes('zbtc/v2/test/r01-other-seed');
const MU = 0x0badc0ffee0ddf00d5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eedn;

function e(index: number, scale = 1n): LinearForm {
  return unitForm(VARIABLES, index, scale);
}

function row(a: LinearForm, b: LinearForm, c: LinearForm, d: LinearForm): Constraint {
  return { a, b, c, d };
}

/** (A,B,C,D): (e1,e1,e0,e2); (e0,e3,e2,e1); (c_star*e0,e0,e2,e3); (e2,e2,e1,e3); (e3,e3,c_star*e0,e1) */
const R01: readonly Constraint[] = [
  row(e(1), e(1), e(0), e(2)),
  row(e(0), e(3), e(2), e(1)),
  row(e(0, C_STAR), e(0), e(2), e(3)),
  row(e(2), e(2), e(1), e(3)),
  row(e(3), e(3), e(0, C_STAR), e(1)),
];
const K = 2 * R01.length + 1;

function encryptR01(seed = SETUP_SEED) {
  return encrypt(R01, MU, seededSampler(seed, AADP_SETUP_DOMAIN));
}

const { ciphertext, setup } = encryptR01();

// ---- Tests ----

describe('R01 relation', () => {
  it('evaluates every row to its hand-derived value on both sides', () => {
    const sides = R01.map((constraint) => constraintSides(constraint, WITNESS));
    expect(sides.map(({ left }) => left)).toEqual(EXPECTED_ROW_VALUES);
    expect(sides.map(({ right }) => right)).toEqual(EXPECTED_ROW_VALUES);
    expect(satisfies(R01, WITNESS)).toBe(true);
  });

  it('is not satisfied by the changed witness', () => {
    expect(satisfies(R01, CHANGED_WITNESS)).toBe(false);
  });
});

describe('AADP on R01 with a fixed seed', () => {
  it('makes S(w) = Σ w_j·M_j singular for the satisfying witness', () => {
    expect(determinant(evaluateMatrices(setup.unmaskedMatrices, WITNESS))).toBe(0n);
  });

  it('has a nonzero recovery cofactor for this seed', () => {
    expect(recoveryCofactor(setup, WITNESS)).not.toBe(0n);
  });

  it('recovers mu exactly from the ciphertext and the witness alone', () => {
    expect(decrypt(ciphertext, WITNESS)).toBe(MU);
  });

  it('sizes the ciphertext at 15,488 bytes', () => {
    expect(ciphertext.matrices).toHaveLength(VARIABLES);
    expect(ciphertext.matrices[0]).toHaveLength(K);
    expect(ciphertextBytes(ciphertext)).toBe(R01_CIPHERTEXT_BYTES);
  });

  it('masks only Mhat_0 at (k-1, k-1), and by exactly mu', () => {
    const differences: [number, number, number][] = [];
    ciphertext.matrices.forEach((masked, variable) =>
      masked.forEach((values, rowIndex) =>
        values.forEach((value, column) => {
          if (value !== setup.unmaskedMatrices[variable][rowIndex][column]) {
            differences.push([variable, rowIndex, column]);
          }
        }),
      ),
    );
    expect(differences).toEqual([[0, K - 1, K - 1]]);
    const last = K - 1;
    expect(mod(ciphertext.matrices[0][last][last] - setup.unmaskedMatrices[0][last][last])).toBe(MU);
  });

  it('replays the same setup from the same seed, and a different one from another seed', () => {
    expect(encryptR01().ciphertext).toEqual(ciphertext);
    expect(encryptR01(OTHER_SEED).ciphertext).not.toEqual(ciphertext);
  });

  // A wrong witness can yield any candidate, mu included; this records one outcome.
  it(
    'illustration only, not a soundness claim: for this seed the changed witness ' +
      '(1, 2, 4, 9) yields a candidate other than mu',
    () => {
      expect(decrypt(ciphertext, CHANGED_WITNESS)).not.toBe(MU);
    },
  );
});

describe('AADP input checks', () => {
  it('rejects a witness whose x0 is not 1', () => {
    expect(() => decrypt(ciphertext, [2n, 4n, 8n, 16n])).toThrow(RangeError);
    expect(() => recoveryCofactor(setup, [0n, 2n, 4n, 8n])).toThrow(RangeError);
  });

  it('rejects a witness of the wrong length', () => {
    expect(() => decrypt(ciphertext, [1n, 2n, 4n])).toThrow(RangeError);
  });

  it('rejects a non-canonical mu', () => {
    const sample = seededSampler(SETUP_SEED, AADP_SETUP_DOMAIN);
    expect(() => encrypt(R01, BASE_FIELD_MODULUS, sample)).toThrow(RangeError);
    expect(() => encrypt(R01, -1n, sample)).toThrow(RangeError);
  });

  it('throws ZeroCofactorError when the leading minor of E vanishes', () => {
    const degenerate = { matrices: [zeroMatrix(K, K), zeroMatrix(K, K)] };
    expect(() => decrypt(degenerate, [1n, 5n])).toThrow(ZeroCofactorError);
  });
});
