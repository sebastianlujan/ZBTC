import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { ADDRESS_PREFIX, BODY_BYTES, MAX_VALUE, R } from '../../src/constants.js';
import {
  bigIntToBytes,
  bytesToHex,
  cm,
  decodeAddress,
  decryptNote,
  encodeAddress,
  encryptNote,
  hBody,
  isValidPkEnc,
  keysFromSeed,
  noteMatches,
  pkEncOf,
  randomField,
} from '../../src/crypto.js';

const alice = keysFromSeed(new Uint8Array(32).fill(0xa1));
const bob = keysFromSeed(new Uint8Array(32).fill(0xb0));

function noteFor(v: bigint, owner: bigint) {
  const rseed = randomField();
  return { v, rseed, cm: cm(v, owner, rseed) };
}

function flip(b: Uint8Array, i: number): Uint8Array {
  const c = b.slice();
  c[i] ^= 0x01;
  return c;
}

const P25519 = (1n << 255n) - 19n;
function uToLe(u: bigint): Uint8Array {
  return bigIntToBytes(u, 32).reverse();
}

describe('keys', () => {
  it('keysFromSeed is deterministic and seed-separated', () => {
    const again = keysFromSeed(new Uint8Array(32).fill(0xa1));
    expect(again.skSpend).toBe(alice.skSpend);
    expect(again.owner).toBe(alice.owner);
    expect(bytesToHex(again.skEnc)).toBe(bytesToHex(alice.skEnc));
    expect(alice.owner).not.toBe(bob.owner);
    expect(bytesToHex(alice.pkEnc)).toBe(bytesToHex(pkEncOf(alice.skEnc)));
    expect(alice.skSpend < R).toBe(true);
    expect(() => keysFromSeed(new Uint8Array(15))).toThrow();
  });
});

describe('note encryption', () => {
  it('round-trips (including v = 0 and v = 2^64 - 1)', () => {
    for (const v of [0n, 30n, MAX_VALUE]) {
      const n = noteFor(v, bob.owner);
      const { epk, ct } = encryptNote({ v, rseed: n.rseed }, bob.pkEnc, n.cm);
      expect(epk).toHaveLength(32);
      expect(ct).toHaveLength(56);
      expect(decryptNote(bob.skEnc, epk, ct, n.cm)).toEqual({ v, rseed: n.rseed });
      expect(noteMatches(v, bob.owner, n.rseed, n.cm)).toBe(true);
    }
  });

  it('uses a fresh ephemeral key per note', () => {
    const n = noteFor(5n, bob.owner);
    const a = encryptNote({ v: n.v, rseed: n.rseed }, bob.pkEnc, n.cm);
    const b = encryptNote({ v: n.v, rseed: n.rseed }, bob.pkEnc, n.cm);
    expect(bytesToHex(a.epk)).not.toBe(bytesToHex(b.epk));
    expect(bytesToHex(a.ct)).not.toBe(bytesToHex(b.ct));
  });

  it('wrong skEnc -> null', () => {
    const n = noteFor(7n, bob.owner);
    const { epk, ct } = encryptNote({ v: n.v, rseed: n.rseed }, bob.pkEnc, n.cm);
    expect(decryptNote(alice.skEnc, epk, ct, n.cm)).toBeNull();
  });

  it('tampered ct or epk -> null', () => {
    const n = noteFor(7n, bob.owner);
    const { epk, ct } = encryptNote({ v: n.v, rseed: n.rseed }, bob.pkEnc, n.cm);
    for (let i = 0; i < ct.length; i++) expect(decryptNote(bob.skEnc, epk, flip(ct, i), n.cm)).toBeNull();
    for (let i = 0; i < epk.length; i++) expect(decryptNote(bob.skEnc, flip(epk, i), ct, n.cm)).toBeNull();
  });

  it('wrong aad cm -> null', () => {
    const n = noteFor(7n, bob.owner);
    const { epk, ct } = encryptNote({ v: n.v, rseed: n.rseed }, bob.pkEnc, n.cm);
    expect(decryptNote(bob.skEnc, epk, ct, (n.cm + 1n) % R)).toBeNull();
    expect(decryptNote(bob.skEnc, epk, ct, R)).toBeNull();
  });

  it('wrong sizes -> null', () => {
    const n = noteFor(7n, bob.owner);
    const { epk, ct } = encryptNote({ v: n.v, rseed: n.rseed }, bob.pkEnc, n.cm);
    expect(decryptNote(bob.skEnc, epk.subarray(1), ct, n.cm)).toBeNull();
    expect(decryptNote(bob.skEnc, epk, ct.subarray(1), n.cm)).toBeNull();
    expect(decryptNote(bob.skEnc, epk, concatBytes(ct, new Uint8Array(1)), n.cm)).toBeNull();
  });

  it('low-order or non-canonical-low-order epk -> null without throwing', () => {
    const n = noteFor(7n, bob.owner);
    const { ct } = encryptNote({ v: n.v, rseed: n.rseed }, bob.pkEnc, n.cm);
    const lowOrderU = [
      0n,
      1n,
      P25519 - 1n,
      325606250916557431795983626356110631294008115727848805560023387167927233504n,
      39382357235489614581723060781553021112529911719440698176882885853963445705823n,
    ];
    const encodings = [
      ...lowOrderU.map(uToLe),
      uToLe(P25519), // non-canonical 0
      uToLe(P25519 + 1n), // non-canonical 1
      (() => {
        const b = uToLe(1n);
        b[31] |= 0x80; // high bit set: masked by RFC 7748 decoding
        return b;
      })(),
    ];
    for (const epk of encodings) {
      expect(() => decryptNote(bob.skEnc, epk, ct, n.cm)).not.toThrow();
      expect(decryptNote(bob.skEnc, epk, ct, n.cm)).toBeNull();
      // noble rejects these before the ladder instead of returning an all-zero secret.
      expect(() => x25519.getSharedSecret(bob.skEnc, epk)).toThrow();
    }
  });

  it('decrypts a ciphertext built independently from the spec; rejects rseed >= r and bad lengths', () => {
    // Independent re-implementation of the scheme, to pin the wire format.
    const seal = (pt: Uint8Array, noteCm: bigint) => {
      const { secretKey: esk, publicKey: epk } = x25519.keygen();
      const shared = x25519.getSharedSecret(esk, bob.pkEnc);
      const k = hkdf(sha256, shared, utf8ToBytes('zbtc/v1/note'), concatBytes(epk, bob.pkEnc), 32);
      return { epk, ct: chacha20poly1305(k, new Uint8Array(12), bigIntToBytes(noteCm)).encrypt(pt) };
    };
    const u64le = (v: bigint) => {
      const b = new Uint8Array(8);
      new DataView(b.buffer).setBigUint64(0, v, true);
      return b;
    };
    const n = noteFor(1234n, bob.owner);
    const ok = seal(concatBytes(u64le(1234n), bigIntToBytes(n.rseed)), n.cm);
    expect(decryptNote(bob.skEnc, ok.epk, ok.ct, n.cm)).toEqual({ v: 1234n, rseed: n.rseed });

    const bigRseed = seal(concatBytes(u64le(1n), bigIntToBytes(R)), n.cm);
    expect(decryptNote(bob.skEnc, bigRseed.epk, bigRseed.ct, n.cm)).toBeNull();

    // A 39-byte plaintext gives a 55-byte ct: rejected by size (and would be by length).
    const short = seal(new Uint8Array(39), n.cm);
    expect(decryptNote(bob.skEnc, short.epk, short.ct, n.cm)).toBeNull();
  });

  it('noteMatches rejects a mismatched cm, owner or value', () => {
    const n = noteFor(9n, bob.owner);
    expect(noteMatches(9n, bob.owner, n.rseed, n.cm)).toBe(true);
    expect(noteMatches(9n, bob.owner, n.rseed, (n.cm + 1n) % R)).toBe(false);
    expect(noteMatches(9n, alice.owner, n.rseed, n.cm)).toBe(false);
    expect(noteMatches(10n, bob.owner, n.rseed, n.cm)).toBe(false);
    expect(noteMatches(9n, bob.owner, (n.rseed + 1n) % R, n.cm)).toBe(false);
    expect(noteMatches(9n, bob.owner, R, n.cm)).toBe(false);
    expect(noteMatches(MAX_VALUE + 1n, bob.owner, n.rseed, n.cm)).toBe(false);
  });

  it('refuses to encrypt to a low-order or non-canonical pkEnc', () => {
    const n = noteFor(1n, bob.owner);
    expect(() => encryptNote({ v: 1n, rseed: n.rseed }, uToLe(1n), n.cm)).toThrow();
    expect(() => encryptNote({ v: 1n, rseed: n.rseed }, uToLe(P25519 + 9n), n.cm)).toThrow();
    expect(() => encryptNote({ v: MAX_VALUE + 1n, rseed: n.rseed }, bob.pkEnc, n.cm)).toThrow();
  });
});

describe('addresses', () => {
  it('round-trips', () => {
    const addr = encodeAddress({ owner: bob.owner, pkEnc: bob.pkEnc });
    expect(addr.startsWith(ADDRESS_PREFIX)).toBe(true);
    expect(addr).toHaveLength(134);
    const back = decodeAddress(addr);
    expect(back.owner).toBe(bob.owner);
    expect(bytesToHex(back.pkEnc)).toBe(bytesToHex(bob.pkEnc));
  });

  it('rejects bad inputs', () => {
    const good = encodeAddress({ owner: bob.owner, pkEnc: bob.pkEnc });
    const body = good.slice(ADDRESS_PREFIX.length);
    const ownerHex = body.slice(0, 64);
    const pkHex = body.slice(64);
    const bad = [
      'zbtcmn' + body, // wrong prefix
      good.slice(0, -1), // too short
      good + '0', // too long
      ADDRESS_PREFIX + body.toUpperCase(), // uppercase hex
      ADDRESS_PREFIX + 'zz' + body.slice(2), // not hex
      ADDRESS_PREFIX + bytesToHex(bigIntToBytes(R)) + pkHex, // owner == r
      ADDRESS_PREFIX + 'ff'.repeat(32) + pkHex, // owner > r
      ADDRESS_PREFIX + ownerHex + bytesToHex(uToLe(1n)), // low-order pkEnc
      ADDRESS_PREFIX + ownerHex + bytesToHex(uToLe(P25519 + 9n)), // non-canonical pkEnc
      '',
    ];
    for (const s of bad) expect(() => decodeAddress(s), s).toThrow();
    expect(() => encodeAddress({ owner: R, pkEnc: bob.pkEnc })).toThrow();
    expect(isValidPkEnc(bob.pkEnc)).toBe(true);
    expect(isValidPkEnc(uToLe(0n))).toBe(false);
  });
});

describe('h_body', () => {
  it('is a deterministic 31-byte value and requires a 316-byte body', () => {
    const body = new Uint8Array(BODY_BYTES).map((_, i) => i & 0xff);
    const h = hBody(body);
    expect(h).toBe(hBody(body.slice()));
    expect(h < 1n << 248n).toBe(true);
    expect(() => hBody(body.subarray(1))).toThrow(RangeError);
    // Matches the spec computed by hand.
    const digest = sha256(concatBytes(utf8ToBytes('zbtc/v1/body'), body));
    expect(h).toBe(BigInt('0x' + bytesToHex(digest.subarray(0, 31))));
  });
});
