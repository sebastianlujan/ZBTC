// prepare and unlock on the R04 toy note with a fixed seed. The recipient side
// (unlock) only ever sees the ciphertext, the envelope and the witness.
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { ciphertextBytes } from '../../src/aadp.js';
import { SECRET_KEY_BYTES } from '../../src/constants.js';
import { envelopeAssociatedData } from '../../src/fixture.js';
import { EnvelopeRejectedError, prepare, unlock } from '../../src/unlock.js';
import { PLACEHOLDER_TXID, testFixture } from '../helpers/fixture.js';

const SECRET_KEY = sha256(utf8ToBytes('zbtc/v2/test/secret-key'));
/** A key that starts with 0x00 must come back at full width, not as 31 bytes. */
const LEADING_ZERO_KEY = Uint8Array.from({ length: SECRET_KEY_BYTES }, (_, index) => index);
/** m = 4 constraints, so k = 2·4 + 1. */
const R04_DIMENSION = 9;
/** (n+1)·k²·32 = 4 · 9² · 32. */
const R04_CIPHERTEXT_BYTES = 10_368;
/** amount changed from 100000 to 100001: breaks the commitment and exit rows. */
const CHANGED_WITNESS = [1n, 3n, 5n, 100_001n];

describe('prepare and unlock', () => {
  const fixture = testFixture();
  const prepared = prepare(fixture, SECRET_KEY);

  it('recovers the exact secret key from the note witness', () => {
    expect(unlock(prepared.ciphertext, prepared.envelope, prepared.witness)).toEqual(SECRET_KEY);
  });

  it('keeps a key with a leading zero byte at full width', () => {
    const { ciphertext, envelope, witness } = prepare(fixture, LEADING_ZERO_KEY);
    expect(unlock(ciphertext, envelope, witness)).toEqual(LEADING_ZERO_KEY);
  });

  it('produces a 9×9 ciphertext of 10,368 bytes', () => {
    expect(prepared.ciphertext.matrices[0]).toHaveLength(R04_DIMENSION);
    expect(ciphertextBytes(prepared.ciphertext)).toBe(R04_CIPHERTEXT_BYTES);
  });

  it('records the first seeded attempt and its nonzero cofactor', () => {
    expect(prepared.setupAttempt).toBe(0);
    expect(prepared.cofactor).not.toBe(0n);
  });

  it('replays the same ciphertext from the same seed', () => {
    expect(prepare(fixture, SECRET_KEY).ciphertext).toEqual(prepared.ciphertext);
  });

  it('rejects an envelope carrying another fixture’s associated data', () => {
    const otherFixture = testFixture({ fundingOutpoint: { txid: PLACEHOLDER_TXID, vout: 1 } });
    const tampered = { ...prepared.envelope, associatedData: envelopeAssociatedData(otherFixture) };
    expect(() => unlock(prepared.ciphertext, tampered, prepared.witness)).toThrow(EnvelopeRejectedError);
  });

  it('does not return the key for a changed witness (illustration only, not a soundness claim)', () => {
    expect(() => unlock(prepared.ciphertext, prepared.envelope, CHANGED_WITNESS)).toThrow();
  });

  it('refuses a secret key of the wrong length', () => {
    expect(() => prepare(fixture, SECRET_KEY.slice(1))).toThrow(RangeError);
  });
});
