// Quadratic relations in the AADP normal form a·b = c·d.
//
// A constraint is four linear forms over the variables x0..xn, so a relation
// with m constraints over n+1 variables is just 4m coefficient rows. x0 is the
// homogenising coordinate: an affine witness sets it to 1, which is how a
// constant enters a homogeneous equation (c_star·e0 reads as "c_star").
import { mod, mul } from './field.js';

/** One coefficient per variable x0..xn. */
export type LinearForm = readonly bigint[];

/** Values for x0..xn, in the same order as every LinearForm. */
export type Witness = readonly bigint[];

/** The equation a·b = c·d. */
export interface Constraint {
  readonly a: LinearForm;
  readonly b: LinearForm;
  readonly c: LinearForm;
  readonly d: LinearForm;
}

export interface ConstraintSides {
  /** a(w)·b(w) */
  readonly left: bigint;
  /** c(w)·d(w) */
  readonly right: bigint;
}

/** scale·e_index: the spec writes coefficient rows as scaled unit vectors. */
export function unitForm(variables: number, index: number, scale = 1n): LinearForm {
  if (!Number.isInteger(index) || index < 0 || index >= variables) {
    throw new RangeError(`unit form index ${index} is outside 0..${variables - 1}`);
  }
  return Array.from({ length: variables }, (_, position) => (position === index ? scale : 0n));
}

export function evaluateForm(form: LinearForm, witness: Witness): bigint {
  if (form.length !== witness.length) {
    throw new RangeError(`form has ${form.length} coefficients but the witness has ${witness.length} values`);
  }
  return mod(form.reduce((sum, coefficient, index) => sum + coefficient * witness[index], 0n));
}

export function constraintSides(constraint: Constraint, witness: Witness): ConstraintSides {
  return {
    left: mul(evaluateForm(constraint.a, witness), evaluateForm(constraint.b, witness)),
    right: mul(evaluateForm(constraint.c, witness), evaluateForm(constraint.d, witness)),
  };
}

export function satisfies(constraints: readonly Constraint[], witness: Witness): boolean {
  return constraints.every((constraint) => {
    const { left, right } = constraintSides(constraint, witness);
    return left === right;
  });
}

/** n+1. Throws unless the relation is non-empty and every form has the same width. */
export function variableCount(constraints: readonly Constraint[]): number {
  if (constraints.length === 0) throw new RangeError('a relation needs at least one constraint');
  const count = constraints[0].a.length;
  const consistent = constraints.every(({ a, b, c, d }) =>
    [a, b, c, d].every((form) => form.length === count),
  );
  if (count === 0 || !consistent) {
    throw new RangeError('every linear form must have one coefficient per variable');
  }
  return count;
}
