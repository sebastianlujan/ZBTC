// The toy note R04: a deliberately weak algebraic commitment whose opening is
// the AADP witness.
//
// Data flow: opening (ownerKey, rho, amount) → issueNote → the public
// constants (ownerTag, noteCommitment, nullifierTag, exitAmount) →
// noteConstraints, the four R04 rows. noteWitness turns the same opening into
// w = (x0, ownerKey, rho, amount).
//
// This is not a secure hash: other openings may exist, and one known note
// offers no anonymity. The relation says nothing about Bitcoin state either;
// the outpoint and recipient are bound only by the envelope's associated data.
import { PAYMENT_SATS } from './constants.js';
import { add, mod, mul, sub } from './field.js';
import { unitForm, type Constraint, type LinearForm, type Witness } from './relation.js';

// ---- Variables ----

/** Positions in w = (x0, ownerKey, rho, amount), the spec's canonical coordinate order. */
const X0 = 0;
const OWNER_KEY = 1;
const RHO = 2;
const AMOUNT = 3;
export const NOTE_VARIABLE_COUNT = 4;

/** An affine witness fixes x0 to 1 (see relation.ts). */
const AFFINE_VALUE = 1n;

// ---- Note ----

/** The note's secrets. With x0 = 1 in front, they are the witness. */
export interface NoteOpening {
  readonly ownerKey: bigint;
  readonly rho: bigint;
  readonly amount: bigint;
}

/** What the note publishes. */
export interface NotePublic {
  readonly ownerTag: bigint;
  readonly noteCommitment: bigint;
  readonly nullifierTag: bigint;
  readonly exitAmount: bigint;
}

/** The spec's fixture opening: ownerKey = 3, rho = 5, and the note pays out exactly the demo payment. */
export const TOY_NOTE_OPENING: NoteOpening = { ownerKey: 3n, rho: 5n, amount: PAYMENT_SATS };

/** ownerTag = ownerKey², noteCommitment = amount + ownerTag + rho, nullifierTag = ownerKey·rho. */
export function issueNote({ ownerKey, rho, amount }: NoteOpening): NotePublic {
  const ownerTag = mul(ownerKey, ownerKey);
  return {
    ownerTag,
    noteCommitment: add(add(amount, ownerTag), rho),
    nullifierTag: mul(ownerKey, rho),
    exitAmount: mod(amount),
  };
}

export function noteWitness({ ownerKey, rho, amount }: NoteOpening): Witness {
  return [AFFINE_VALUE, mod(ownerKey), mod(rho), mod(amount)];
}

// ---- Relation ----

function unit(index: number, scale = 1n): LinearForm {
  return unitForm(NOTE_VARIABLE_COUNT, index, scale);
}

const ZERO_FORM: LinearForm = Array.from({ length: NOTE_VARIABLE_COUNT }, () => 0n);

function sumForms(...forms: LinearForm[]): LinearForm {
  return ZERO_FORM.map((_, variable) => forms.reduce((sum, form) => add(sum, form[variable]), 0n));
}

/** The four R04 rows (A, B, C, D), each read as A·B = C·D, in the spec's order. */
export function noteConstraints(note: NotePublic): Constraint[] {
  const { ownerTag, noteCommitment, nullifierTag, exitAmount } = note;
  const commitmentOffset = sub(ownerTag, noteCommitment);
  return [
    // ownerKey·ownerKey = ownerTag·x0·x0
    { a: unit(OWNER_KEY), b: unit(OWNER_KEY), c: unit(X0, ownerTag), d: unit(X0) },
    // (amount + rho + (ownerTag − noteCommitment)·x0)·x0 = 0
    { a: sumForms(unit(AMOUNT), unit(RHO), unit(X0, commitmentOffset)), b: unit(X0), c: ZERO_FORM, d: ZERO_FORM },
    // ownerKey·rho = nullifierTag·x0·x0
    { a: unit(OWNER_KEY), b: unit(RHO), c: unit(X0, nullifierTag), d: unit(X0) },
    // amount·x0 = exitAmount·x0·x0
    { a: unit(AMOUNT), b: unit(X0), c: unit(X0, exitAmount), d: unit(X0) },
  ];
}
