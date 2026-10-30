// AADP witness encryption over F_q: Algorithms 1–3 of the paper, for a
// relation of m constraints a_i·b_i = c_i·d_i over variables x0..xn.
//
// Data flow: constraints + sampler → M_0..M_n (Algorithm 1) → mask M_0 with
// mu·delta to get the public ciphertext Mhat_0..Mhat_n (Algorithm 2) →
// a witness w collapses it to one k×k matrix E whose determinant ratio is mu
// (Algorithm 3). k = 2m + 1.
//
// Why recovery works. For each constraint, U_i(w) = Σ_j w_j·U_i^(j) is
//   [[A, C, -Ξ, 0], [D, B, 0, Ξ], [0, 0, B, C], [0, 0, D, A]]
// with A = a_i(w), ..., Ξ = Σ_j w_j·xi_ij. When A·B = C·D, column 2 is a
// multiple of column 1 and column 4 a combination of columns 1 and 3, so
// rank U_i(w) ≤ 2. Hence S(w) = Σ_j w_j·M_j = Σ_i L_i·U_i(w)·R_i has rank
// ≤ 2m < k and det S(w) = 0. With w_0 = 1, E = S(w) + mu·delta, and the
// determinant is linear in the (k-1, k-1) entry:
//   det E = det S(w) + mu·det(leading minor of S(w)) = mu·minor.
// E and S(w) differ only at (k-1, k-1), which the leading minor drops, so
// det E / det(leading minor of E) = mu whenever that minor is nonzero.
import { AADP_BLOCK_SIZE, FIELD_ELEMENT_BYTES, SATISFIED_BLOCK_RANK } from './constants.js';
import {
  determinant,
  inverse,
  isFieldElement,
  leadingMinor,
  matrixAdd,
  matrixMultiply,
  matrixScale,
  mod,
  mul,
  zeroMatrix,
  type Matrix,
  type Sampler,
} from './field.js';
import { variableCount, type Constraint, type Witness } from './relation.js';

/** Index of x0, the homogenising coordinate that carries mu·delta. */
const AFFINE_VARIABLE = 0;
/** An affine witness fixes x0 to 1, so E picks up exactly one copy of mu·delta. */
const AFFINE_VALUE = 1n;

/** Public: Mhat_0..Mhat_n. A recipient needs only this and a witness. */
export interface Ciphertext {
  readonly matrices: readonly Matrix[];
}

/** Setup-only: the unmasked M_0..M_n. Next to the ciphertext they reveal mu (Mhat_0 - M_0 = mu·delta). */
export interface SetupMatrices {
  readonly unmaskedMatrices: readonly Matrix[];
}

export interface Encryption {
  readonly ciphertext: Ciphertext;
  readonly setup: SetupMatrices;
}

/** The leading minor of E is zero, so det(E - t·delta) = 0 does not determine t. */
export class ZeroCofactorError extends Error {
  override readonly name = 'ZeroCofactorError';

  constructor() {
    super('leading minor of E is zero: this setup cannot recover mu for this witness');
  }
}

// ---- Algorithm 1: coefficient matrices ----

/** k = 2m + 1: one dimension more than the largest rank a satisfying witness can reach. */
function matrixDimension(constraintCount: number): number {
  return SATISFIED_BLOCK_RANK * constraintCount + 1;
}

function randomMatrix(rows: number, columns: number, sample: Sampler): Matrix {
  return Array.from({ length: rows }, () => Array.from({ length: columns }, () => sample()));
}

/** U_i^(j): the block a constraint contributes for variable x_j. */
function uBlock({ a, b, c, d }: Constraint, variable: number, xi: bigint): Matrix {
  const [aj, bj, cj, dj] = [a, b, c, d].map((form) => mod(form[variable]));
  return [
    [aj, cj, mod(-xi), 0n],
    [dj, bj, 0n, xi],
    [0n, 0n, bj, cj],
    [0n, 0n, dj, aj],
  ];
}

/**
 * L_i·U_i^(j)·R_i for every variable j. Sampling order is L_i (row-major),
 * then R_i, then xi_i0..xi_in; a recorded seed replays it exactly.
 */
function constraintContributions(
  constraint: Constraint,
  variables: number,
  k: number,
  sample: Sampler,
): Matrix[] {
  const left = randomMatrix(k, AADP_BLOCK_SIZE, sample);
  const right = randomMatrix(AADP_BLOCK_SIZE, k, sample);
  const xi = Array.from({ length: variables }, () => sample());
  return xi.map((xiOfVariable, variable) =>
    matrixMultiply(matrixMultiply(left, uBlock(constraint, variable, xiOfVariable)), right),
  );
}

/** Algorithm 1: M_j = Σ_i L_i·U_i^(j)·R_i for j = 0..n. */
export function generateMatrices(constraints: readonly Constraint[], sample: Sampler): Matrix[] {
  const variables = variableCount(constraints);
  const k = matrixDimension(constraints.length);
  let matrices: Matrix[] = Array.from({ length: variables }, () => zeroMatrix(k, k));
  for (const constraint of constraints) {
    const contributions = constraintContributions(constraint, variables, k, sample);
    matrices = matrices.map((matrix, variable) => matrixAdd(matrix, contributions[variable]));
  }
  return matrices;
}

// ---- Algorithm 2: encryption ----

/** delta: the k×k matrix with a single 1 at (k-1, k-1). */
function deltaMatrix(k: number): Matrix {
  const last = k - 1;
  return Array.from({ length: k }, (_, row) =>
    Array.from({ length: k }, (_, column) => (row === last && column === last ? 1n : 0n)),
  );
}

/** k, read from a non-empty list of k×k matrices. */
function sideLength(matrices: readonly Matrix[]): number {
  if (matrices.length === 0) throw new RangeError('expected at least one matrix');
  return matrices[0].length;
}

/** Algorithm 2: Mhat_0 = M_0 + mu·delta and Mhat_j = M_j for j ≥ 1. */
export function encrypt(constraints: readonly Constraint[], mu: bigint, sample: Sampler): Encryption {
  if (!isFieldElement(mu)) throw new RangeError('mu must be a canonical element of F_q');
  const unmaskedMatrices = generateMatrices(constraints, sample);
  const mask = matrixScale(deltaMatrix(sideLength(unmaskedMatrices)), mu);
  const matrices = unmaskedMatrices.map((matrix, variable) =>
    variable === AFFINE_VARIABLE ? matrixAdd(matrix, mask) : matrix,
  );
  return { ciphertext: { matrices }, setup: { unmaskedMatrices } };
}

// ---- Algorithm 3: decryption ----

function assertAffineWitness(witness: Witness, variables: number): void {
  if (witness.length !== variables) {
    throw new RangeError(`witness has ${witness.length} values but the matrices need ${variables}`);
  }
  if (witness[AFFINE_VARIABLE] !== AFFINE_VALUE) throw new RangeError('witness[0] must be 1');
}

/** Σ_j w_j·matrices_j, for an affine witness (w_0 = 1). */
export function evaluateMatrices(matrices: readonly Matrix[], witness: Witness): Matrix {
  assertAffineWitness(witness, matrices.length);
  const k = sideLength(matrices);
  return matrices.reduce<Matrix>(
    (sum, matrix, variable) => matrixAdd(sum, matrixScale(matrix, witness[variable])),
    zeroMatrix(k, k),
  );
}

/** Algorithm 3: t = det(E) / det(leading minor of E), the root of det(E - t·delta) = 0. */
export function decrypt(ciphertext: Ciphertext, witness: Witness): bigint {
  const evaluated = evaluateMatrices(ciphertext.matrices, witness);
  const minor = determinant(leadingMinor(evaluated));
  if (minor === 0n) throw new ZeroCofactorError();
  return mul(determinant(evaluated), inverse(minor));
}

/** det(leading minor of S(w)): the setup checks it is nonzero before publishing. */
export function recoveryCofactor(setup: SetupMatrices, witness: Witness): bigint {
  return determinant(leadingMinor(evaluateMatrices(setup.unmaskedMatrices, witness)));
}

/** Dense size, (n+1)·k²·32 bytes, excluding framing and the envelope. */
export function ciphertextBytes(ciphertext: Ciphertext): number {
  const k = sideLength(ciphertext.matrices);
  return ciphertext.matrices.length * k * k * FIELD_ELEMENT_BYTES;
}
