// BIP341 key tweaking against the pinned official vectors, plus the two
// properties the demo relies on: secret keys are always 32 bytes, and the
// tweaked secret key signs for the tweaked output key whatever the parity of d·G.
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { SECRET_KEY_BYTES } from '../../src/constants.js';
import {
  generateSecretKey,
  internalKey,
  outputScript,
  tapTweak,
  tweakPublicKey,
  tweakSecretKey,
} from '../../src/taproot.js';
import { BIP341 } from '../helpers/bip341.js';

/** With 64 fresh keys, missing either parity of d·G has probability 2^-63. */
const RANDOM_KEY_SAMPLES = 64;
/** SEC1 compressed prefixes: 0x02 for even Y, 0x03 for odd Y. */
const BOTH_PARITY_PREFIXES = new Set([0x02, 0x03]);

function tweakHex(tweak: bigint): string {
  return tweak.toString(16).padStart(2 * SECRET_KEY_BYTES, '0');
}

describe('BIP341 output key without a script tree', () => {
  const { given, intermediary, expected } = BIP341.scriptPubKey;
  const internal = hexToBytes(given.internalPubkey);

  it('derives the tweak', () => {
    expect(tweakHex(tapTweak(internal))).toBe(intermediary.tweak);
  });

  it('derives the output key and its scriptPubKey', () => {
    const outputKey = tweakPublicKey(internal);
    expect(bytesToHex(outputKey)).toBe(intermediary.tweakedPubkey);
    expect(bytesToHex(outputScript(outputKey))).toBe(expected.scriptPubKey);
  });
});

describe('BIP341 tweaked secret key', () => {
  const { given, intermediary } = BIP341.keyPathSpending.inputSpending;
  const secretKey = hexToBytes(given.internalPrivkey);
  const merkleRoot = hexToBytes(given.merkleRoot);

  it('derives the internal key', () => {
    expect(bytesToHex(internalKey(secretKey))).toBe(intermediary.internalPubkey);
  });

  it('derives the tweak over the merkle root', () => {
    expect(tweakHex(tapTweak(internalKey(secretKey), merkleRoot))).toBe(intermediary.tweak);
  });

  it('derives the tweaked secret key', () => {
    expect(bytesToHex(tweakSecretKey(secretKey, merkleRoot))).toBe(intermediary.tweakedPrivkey);
  });
});

describe('demo keys', () => {
  const secretKeys = Array.from({ length: RANDOM_KEY_SAMPLES }, () => generateSecretKey());

  it('are always 32 bytes', () => {
    expect(secretKeys.every((secretKey) => secretKey.length === SECRET_KEY_BYTES)).toBe(true);
  });

  it('cover both parities of d·G in this sample', () => {
    const prefixes = new Set(secretKeys.map((secretKey) => secp256k1.getPublicKey(secretKey, true)[0]));
    expect(prefixes).toEqual(BOTH_PARITY_PREFIXES);
  });

  it('tweak to a secret key whose public key is the output key', () => {
    for (const secretKey of secretKeys) {
      expect(schnorr.getPublicKey(tweakSecretKey(secretKey))).toEqual(tweakPublicKey(internalKey(secretKey)));
    }
  });

  it('refuse a secret key of the wrong length', () => {
    expect(() => tweakSecretKey(new Uint8Array(SECRET_KEY_BYTES - 1))).toThrow(RangeError);
  });
});
