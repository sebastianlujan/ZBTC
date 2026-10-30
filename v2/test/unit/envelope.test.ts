// The mu-keyed AEAD envelope: exact round trips for any 32-byte key, and null
// (never an exception) for a wrong mu, tampering or a malformed envelope.
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { BASE_FIELD_MODULUS, ENVELOPE_NONCE_BYTES } from '../../src/constants.js';
import { seal, unseal, type SealedEnvelope } from '../../src/envelope.js';

const POLY1305_TAG_BYTES = 16;
const KEY_BYTES = 32;
const MU = 0x1f00d5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5een;
const ASSOCIATED_DATA = utf8ToBytes('zbtc/v2/test/fixture-metadata');

/**
 * Starts with 0x00. Codex's prototype read keys back through createECDH, which
 * strips leading zero bytes, so keys like this one came out 31 bytes long.
 */
const KEY_WITH_LEADING_ZERO = Uint8Array.from({ length: KEY_BYTES }, (_, index) => index);
const KEY_WITH_TWO_LEADING_ZEROS = Uint8Array.from({ length: KEY_BYTES }, (_, index) =>
  index < 2 ? 0x00 : 0xa5,
);
const KEY_ALL_ONES = new Uint8Array(KEY_BYTES).fill(0xff);

function flipFirstBit(bytes: Uint8Array): Uint8Array {
  const copy = bytes.slice();
  copy[0] ^= 0x01;
  return copy;
}

function sealDefault(plaintext: Uint8Array = KEY_WITH_LEADING_ZERO): SealedEnvelope {
  return seal(MU, plaintext, ASSOCIATED_DATA);
}

describe('envelope round trip', () => {
  it.each([
    ['a leading 0x00 byte', KEY_WITH_LEADING_ZERO],
    ['two leading 0x00 bytes', KEY_WITH_TWO_LEADING_ZEROS],
    ['every byte 0xff', KEY_ALL_ONES],
  ])('returns a 32-byte key with %s unchanged', (_, key) => {
    const opened = unseal(MU, seal(MU, key, ASSOCIATED_DATA), ASSOCIATED_DATA);
    expect(opened).toEqual(key);
    expect(opened).toHaveLength(KEY_BYTES);
  });

  it('accepts any canonical mu, including ones with leading zero bytes', () => {
    for (const mu of [0n, 42n, BASE_FIELD_MODULUS - 1n]) {
      const sealed = seal(mu, KEY_ALL_ONES, ASSOCIATED_DATA);
      expect(unseal(mu, sealed, ASSOCIATED_DATA)).toEqual(KEY_ALL_ONES);
    }
  });

  it('uses a fresh 24-byte nonce and appends a 16-byte tag', () => {
    const first = sealDefault();
    const second = sealDefault();
    expect(first.nonce).toHaveLength(ENVELOPE_NONCE_BYTES);
    expect(first.ciphertext).toHaveLength(KEY_BYTES + POLY1305_TAG_BYTES);
    expect(first.nonce).not.toEqual(second.nonce);
  });

  it('refuses to seal under a non-canonical mu', () => {
    expect(() => seal(BASE_FIELD_MODULUS, KEY_ALL_ONES, ASSOCIATED_DATA)).toThrow(RangeError);
  });
});

describe('envelope rejection', () => {
  const sealed = sealDefault();

  it('returns null for a wrong mu', () => {
    expect(unseal(MU + 1n, sealed, ASSOCIATED_DATA)).toBeNull();
  });

  it('returns null for tampered associated data', () => {
    expect(unseal(MU, sealed, flipFirstBit(ASSOCIATED_DATA))).toBeNull();
  });

  it('returns null for a tampered ciphertext or nonce', () => {
    const tamperedCiphertext = { ...sealed, ciphertext: flipFirstBit(sealed.ciphertext) };
    const tamperedNonce = { ...sealed, nonce: flipFirstBit(sealed.nonce) };
    expect(unseal(MU, tamperedCiphertext, ASSOCIATED_DATA)).toBeNull();
    expect(unseal(MU, tamperedNonce, ASSOCIATED_DATA)).toBeNull();
  });

  it('returns null instead of throwing for a malformed envelope or a non-canonical mu', () => {
    expect(unseal(MU, { ...sealed, nonce: sealed.nonce.subarray(1) }, ASSOCIATED_DATA)).toBeNull();
    expect(unseal(MU, { ...sealed, ciphertext: new Uint8Array(0) }, ASSOCIATED_DATA)).toBeNull();
    expect(unseal(BASE_FIELD_MODULUS, sealed, ASSOCIATED_DATA)).toBeNull();
  });
});
