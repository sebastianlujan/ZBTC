// Arithmetic over the BN254 base field F_q, dense matrices over it, and a
// deterministic sampler.
//
// Scalars are canonical residues in [0, q). Matrices are row-major arrays of
// rows; every helper reduces its results, so callers may pass unreduced
// coefficients (a negative relation coefficient, say). The seeded sampler turns
// a recorded seed into the exact same stream of field elements, which lets a
// setup be replayed bit for bit.
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { BASE_FIELD_MODULUS, FIELD_ELEMENT_BYTES, SAMPLER_COUNTER_BYTES } from './constants.js';

export type Matrix = readonly (readonly bigint[])[];

/** Produces one uniformly distributed element of F_q per call. */
export type Sampler = () => bigint;

// ---- Scalars ----

/** Canonical residue in [0, q). */
export function mod(value: bigint): bigint {
  const remainder = value % BASE_FIELD_MODULUS;
  return remainder < 0n ? remainder + BASE_FIELD_MODULUS : remainder;
}

export function add(left: bigint, right: bigint): bigint {
  return mod(left + right);
}

export function sub(left: bigint, right: bigint): bigint {
  return mod(left - right);
}

export function mul(left: bigint, right: bigint): bigint {
  return mod(left * right);
}

/** Multiplicative inverse by the extended Euclidean algorithm. */
export function inverse(value: bigint): bigint {
  const reduced = mod(value);
  if (reduced === 0n) throw new RangeError('zero has no inverse in F_q');
  let [remainder, nextRemainder] = [BASE_FIELD_MODULUS, reduced];
  let [coefficient, nextCoefficient] = [0n, 1n];
  while (nextRemainder !== 0n) {
    const quotient = remainder / nextRemainder;
    [remainder, nextRemainder] = [nextRemainder, remainder - quotient * nextRemainder];
    [coefficient, nextCoefficient] = [nextCoefficient, coefficient - quotient * nextCoefficient];
  }
  return mod(coefficient);
}

export function isFieldElement(value: bigint): boolean {
  return value >= 0n && value < BASE_FIELD_MODULUS;
}

/**
 * Fixed-width big-endian bytes. The width never depends on the value, so a
 * small element (or one with leading zero bytes) still encodes to 32 bytes.
 */
export function encodeFieldElement(value: bigint): Uint8Array {
  if (!isFieldElement(value)) throw new RangeError('value is not a canonical element of F_q');
  return hexToBytes(value.toString(16).padStart(2 * FIELD_ELEMENT_BYTES, '0'));
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt(`0x${bytesToHex(bytes)}`);
}

// ---- Matrices ----

export function zeroMatrix(rows: number, columns: number): Matrix {
  return Array.from({ length: rows }, () => Array.from({ length: columns }, () => 0n));
}

function assertSameShape(left: Matrix, right: Matrix): void {
  const sameShape =
    left.length === right.length && left.every((row, index) => row.length === right[index].length);
  if (!sameShape) throw new RangeError('matrices must have the same shape');
}

export function matrixAdd(left: Matrix, right: Matrix): Matrix {
  assertSameShape(left, right);
  return left.map((row, rowIndex) => row.map((value, column) => add(value, right[rowIndex][column])));
}

export function matrixScale(matrix: Matrix, scalar: bigint): Matrix {
  return matrix.map((row) => row.map((value) => mul(value, scalar)));
}

/** Each entry accumulates unreduced and is reduced once, which keeps the inner loop cheap. */
export function matrixMultiply(left: Matrix, right: Matrix): Matrix {
  const inner = right.length;
  if (left.some((row) => row.length !== inner)) {
    throw new RangeError('left column count must equal right row count');
  }
  const columns = inner === 0 ? 0 : right[0].length;
  return left.map((row) =>
    Array.from({ length: columns }, (_, column) =>
      mod(row.reduce((sum, value, index) => sum + value * right[index][column], 0n)),
    ),
  );
}

/** The leading (k-1)×(k-1) submatrix: the last row and column dropped. */
export function leadingMinor(matrix: Matrix): Matrix {
  return matrix.slice(0, -1).map((row) => row.slice(0, -1));
}

// ---- Determinant ----

function findPivotRow(rows: bigint[][], column: number): number | undefined {
  for (let row = column; row < rows.length; row++) {
    if (rows[row][column] !== 0n) return row;
  }
  return undefined;
}

/** Clears every entry below the pivot; row operations of this kind leave the determinant unchanged. */
function eliminateBelow(rows: bigint[][], column: number): void {
  const pivotInverse = inverse(rows[column][column]);
  for (let row = column + 1; row < rows.length; row++) {
    const factor = mul(rows[row][column], pivotInverse);
    if (factor === 0n) continue;
    for (let entry = column; entry < rows.length; entry++) {
      rows[row][entry] = sub(rows[row][entry], mul(factor, rows[column][entry]));
    }
  }
}

/**
 * Gaussian elimination mod q. The result is the product of the pivots, with
 * one sign flip per row swap; a column without a pivot means the matrix is singular.
 */
export function determinant(matrix: Matrix): bigint {
  if (matrix.some((row) => row.length !== matrix.length)) {
    throw new RangeError('determinant needs a square matrix');
  }
  const rows = matrix.map((row) => row.map(mod));
  let result = 1n;
  for (let column = 0; column < rows.length; column++) {
    const pivotRow = findPivotRow(rows, column);
    if (pivotRow === undefined) return 0n;
    if (pivotRow !== column) {
      [rows[pivotRow], rows[column]] = [rows[column], rows[pivotRow]];
      result = mod(-result);
    }
    result = mul(result, rows[column][column]);
    eliminateBelow(rows, column);
  }
  return result;
}

// ---- Deterministic sampler ----

/** Masking a hash to q's 254 bits accepts about 76% of candidates; rejecting the rest keeps the output unbiased. */
const FIELD_BIT_MASK = (1n << BigInt(BASE_FIELD_MODULUS.toString(2).length)) - 1n;
const MAX_SAMPLER_COUNTER = 2 ** (8 * SAMPLER_COUNTER_BYTES) - 1;

function counterBytes(counter: number): Uint8Array {
  if (counter > MAX_SAMPLER_COUNTER) throw new RangeError('seeded sampler exhausted its u32 counter');
  const bytes = new Uint8Array(SAMPLER_COUNTER_BYTES);
  new DataView(bytes.buffer).setUint32(0, counter); // DataView writes big-endian by default.
  return bytes;
}

/**
 * Candidate i is sha256(seed ‖ utf8(tag) ‖ u32be(i)) masked to q's bit length;
 * candidates ≥ q are rejected, so accepted values are uniform in F_q. The
 * counter advances on every candidate, accepted or not, so the stream depends
 * only on (seed, tag).
 */
export function seededSampler(seed: Uint8Array, tag: string): Sampler {
  const prefix = concatBytes(seed, utf8ToBytes(tag));
  let counter = 0;
  return () => {
    for (;;) {
      const digest = sha256(concatBytes(prefix, counterBytes(counter)));
      counter += 1;
      const candidate = bytesToBigInt(digest) & FIELD_BIT_MASK;
      if (candidate < BASE_FIELD_MODULUS) return candidate;
    }
  };
}
