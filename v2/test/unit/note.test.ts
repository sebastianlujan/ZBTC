// The toy note R04 (docs/codex_plan.md) with the spec's opening
// (ownerKey, rho, amount) = (3, 5, 100000).
import { describe, expect, it } from 'vitest';
import {
  issueNote,
  NOTE_VARIABLE_COUNT,
  noteConstraints,
  noteWitness,
  TOY_NOTE_OPENING,
} from '../../src/note.js';
import { constraintSides, satisfies } from '../../src/relation.js';

const EXPECTED_PUBLIC = { ownerTag: 9n, noteCommitment: 100_014n, nullifierTag: 15n, exitAmount: 100_000n };
const EXPECTED_WITNESS = [1n, 3n, 5n, 100_000n];
const EXPECTED_ROW_VALUES = [9n, 0n, 15n, 100_000n];
const ZERO_FORM = Array.from({ length: NOTE_VARIABLE_COUNT }, () => 0n);
const COMMITMENT_ROW = 1;

describe('R04 toy note', () => {
  const constraints = noteConstraints(issueNote(TOY_NOTE_OPENING));
  const witness = noteWitness(TOY_NOTE_OPENING);

  it('publishes the spec constants for the fixture opening', () => {
    expect(issueNote(TOY_NOTE_OPENING)).toEqual(EXPECTED_PUBLIC);
  });

  it('orders the witness as (x0, ownerKey, rho, amount)', () => {
    expect(witness).toEqual(EXPECTED_WITNESS);
  });

  it('evaluates each row to the expected value on both sides', () => {
    const sides = constraints.map((constraint) => constraintSides(constraint, witness));
    expect(sides).toEqual(EXPECTED_ROW_VALUES.map((value) => ({ left: value, right: value })));
  });

  it('uses the zero form for C and D in the commitment row, as the spec does', () => {
    expect(constraints[COMMITMENT_ROW].c).toEqual(ZERO_FORM);
    expect(constraints[COMMITMENT_ROW].d).toEqual(ZERO_FORM);
  });

  it('is satisfied by its own opening', () => {
    expect(satisfies(constraints, witness)).toBe(true);
  });

  it('is not satisfied by a different owner key against the same public note', () => {
    const otherWitness = noteWitness({ ...TOY_NOTE_OPENING, ownerKey: 4n });
    expect(satisfies(constraints, otherWitness)).toBe(false);
  });
});
