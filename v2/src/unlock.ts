// The two halves of the note's cryptography (P04).
//
// prepare (setup operator, trusted): note opening → R04 constraints and
// witness → for attempt 0, 1, …: sample mu and the matrices from the recorded
// seed, keep the first attempt whose recovery cofactor is nonzero → seal the
// Bitcoin secret key under mu.
//
// unlock (recipient): ciphertext + witness → mu (Algorithm 3) → unseal the
// key. It accepts no setup value at all, so the only way it can return the key
// is by actually decrypting.
import { decrypt, encrypt, recoveryCofactor, type Ciphertext } from './aadp.js';
import { AADP_SETUP_DOMAIN, MAX_SETUP_ATTEMPTS, MU_DOMAIN, SECRET_KEY_BYTES } from './constants.js';
import { seal, unseal, type SealedEnvelope } from './envelope.js';
import { seededSampler } from './field.js';
import { envelopeAssociatedData, type Fixture } from './fixture.js';
import { issueNote, noteConstraints, noteWitness } from './note.js';
import { satisfies, type Constraint, type Witness } from './relation.js';

export interface NoteEnvelope {
  readonly sealed: SealedEnvelope;
  /** The public terms the AEAD authenticates. They travel with the envelope, so unlock needs no fixture. */
  readonly associatedData: Uint8Array;
}

export interface PreparedNote {
  readonly ciphertext: Ciphertext;
  readonly envelope: NoteEnvelope;
  readonly witness: Witness;
  /** The seeded attempt that produced the ciphertext; replaying the seed needs it. */
  readonly setupAttempt: number;
  /** det of the leading minor of S(w). Nonzero, which is why unlock can recover mu. */
  readonly cofactor: bigint;
}

export class SetupExhaustedError extends Error {
  override readonly name = 'SetupExhaustedError';

  constructor(readonly attempts: number) {
    super(`all ${attempts} setup attempts had a zero recovery cofactor`);
  }
}

export class EnvelopeRejectedError extends Error {
  override readonly name = 'EnvelopeRejectedError';

  constructor() {
    super('the recovered mu does not open the envelope');
  }
}

// ---- Setup ----

interface SetupAttempt {
  readonly mu: bigint;
  readonly ciphertext: Ciphertext;
  readonly cofactor: bigint;
}

/** mu and the matrices use separate tags, so drawing one never shifts the other's stream. */
function attemptSetup(
  constraints: readonly Constraint[],
  witness: Witness,
  seed: Uint8Array,
  attempt: number,
): SetupAttempt {
  const mu = seededSampler(seed, `${MU_DOMAIN}/${attempt}`)();
  const matrixSampler = seededSampler(seed, `${AADP_SETUP_DOMAIN}/${attempt}`);
  const { ciphertext, setup } = encrypt(constraints, mu, matrixSampler);
  return { mu, ciphertext, cofactor: recoveryCofactor(setup, witness) };
}

function assertPreparable(constraints: readonly Constraint[], witness: Witness, secretKey: Uint8Array): void {
  if (secretKey.length !== SECRET_KEY_BYTES) throw new RangeError(`secret key must be ${SECRET_KEY_BYTES} bytes`);
  if (!satisfies(constraints, witness)) throw new RangeError('the note opening does not satisfy its own constraints');
}

function sealKey(fixture: Fixture, mu: bigint, secretKey: Uint8Array): NoteEnvelope {
  const associatedData = envelopeAssociatedData(fixture);
  return { sealed: seal(mu, secretKey, associatedData), associatedData };
}

/** Setup side. Throws SetupExhaustedError if no attempt yields a nonzero cofactor. */
export function prepare(fixture: Fixture, secretKey: Uint8Array): PreparedNote {
  const constraints = noteConstraints(issueNote(fixture.note));
  const witness = noteWitness(fixture.note);
  assertPreparable(constraints, witness, secretKey);
  for (let attempt = 0; attempt < MAX_SETUP_ATTEMPTS; attempt++) {
    const { mu, ciphertext, cofactor } = attemptSetup(constraints, witness, fixture.seed, attempt);
    if (cofactor === 0n) continue;
    const envelope = sealKey(fixture, mu, secretKey);
    return { ciphertext, envelope, witness, setupAttempt: attempt, cofactor };
  }
  throw new SetupExhaustedError(MAX_SETUP_ATTEMPTS);
}

// ---- Recipient ----

/** Recipient side. The AEAD tag is the only check that the recovered mu is the right one. */
export function unlock(ciphertext: Ciphertext, envelope: NoteEnvelope, witness: Witness): Uint8Array {
  const mu = decrypt(ciphertext, witness);
  const secretKey = unseal(mu, envelope.sealed, envelope.associatedData);
  if (secretKey === null) throw new EnvelopeRejectedError();
  return secretKey;
}
