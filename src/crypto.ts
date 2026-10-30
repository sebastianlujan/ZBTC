// Field arithmetic helpers, Poseidon note primitives, key derivation, note
// encryption and h_body.
//
// Poseidon comes from poseidon-lite, which uses the same constants as
// circomlib's Poseidon template (test C1 checks JS and circuit agree).
// Note encryption is X25519 + HKDF-SHA256 + ChaCha20-Poly1305 with aad = cm.
// It happens OUTSIDE the circuit: a sender can publish garbage ct for a valid
// cm, and the receiver then cannot spend that note (documented deviation).
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { poseidon2 } from 'poseidon-lite/poseidon2';
import { poseidon4 } from 'poseidon-lite/poseidon4';
import {
  ADDRESS_LENGTH,
  ADDRESS_PREFIX,
  BODY_BYTES,
  CT_BYTES,
  DOM_CM,
  DOM_NF,
  DOM_NFK,
  DOM_OWN,
  EPK_BYTES,
  FIELD_BYTES,
  H_BODY_BYTES,
  H_BODY_DOMAIN,
  KDF_INFO_ENC,
  KDF_INFO_SPEND,
  KDF_SALT,
  MAX_VALUE,
  NOTE_KDF_SALT,
  NOTE_PLAINTEXT_BYTES,
  R,
} from './constants.js';

// ---- Bigint / byte helpers ----

/** Big-endian bytes -> bigint. */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt('0x' + bytesToHex(bytes));
}

/** bigint -> fixed-width big-endian bytes. Throws if x is negative or does not fit. */
export function bigIntToBytes(x: bigint, length = FIELD_BYTES): Uint8Array {
  if (x < 0n) throw new RangeError('negative bigint');
  const hex = x.toString(16);
  if (hex.length > length * 2) throw new RangeError(`bigint does not fit in ${length} bytes`);
  return hexToBytes(hex.padStart(length * 2, '0'));
}

const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;

/** True for a string of decimal digits without leading zeros (one encoding per value). */
export function isCanonicalDecimal(s: unknown): s is string {
  return typeof s === 'string' && CANONICAL_DECIMAL.test(s);
}

/** Canonical residue in [0, R). */
export function modR(x: bigint): bigint {
  const m = x % R;
  return m < 0n ? m + R : m;
}

/** True when x is a canonical field element (0 <= x < R). */
export function isField(x: bigint): boolean {
  return x >= 0n && x < R;
}

/** Throws unless x is a canonical field element. */
export function assertField(x: bigint, what = 'value'): bigint {
  if (!isField(x)) throw new RangeError(`${what} is not a canonical field element`);
  return x;
}

export { bytesToHex, concatBytes, hexToBytes };

/** 64 uniformly random bytes reduced mod R (bias < 2^-250). */
export function randomField(): bigint {
  return modR(bytesToBigInt(randomBytes(64)));
}

function u64ToLe(v: bigint): Uint8Array {
  if (v < 0n || v > MAX_VALUE) throw new RangeError('value is not a u64');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, true);
  return out;
}

function leToU64(bytes: Uint8Array): bigint {
  return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
}

// ---- Note primitives (mirror the circuit exactly) ----

/** owner = Poseidon(DOM_OWN, sk_spend). */
export function ownerOf(skSpend: bigint): bigint {
  return poseidon2([DOM_OWN, assertField(skSpend, 'skSpend')]);
}

/** sk_nf = Poseidon(DOM_NFK, sk_spend). */
export function skNfOf(skSpend: bigint): bigint {
  return poseidon2([DOM_NFK, assertField(skSpend, 'skSpend')]);
}

/** cm = Poseidon(DOM_CM, v, owner, rseed). */
export function cm(v: bigint, owner: bigint, rseed: bigint): bigint {
  return poseidon4([
    DOM_CM,
    assertField(v, 'v'),
    assertField(owner, 'owner'),
    assertField(rseed, 'rseed'),
  ]);
}

/** nf = Poseidon(DOM_NF, sk_nf, rseed, pos). */
export function nf(skNf: bigint, rseed: bigint, pos: bigint | number): bigint {
  return poseidon4([
    DOM_NF,
    assertField(skNf, 'skNf'),
    assertField(rseed, 'rseed'),
    assertField(BigInt(pos), 'pos'),
  ]);
}

/** Poseidon(2) node hash of the note tree. */
export function hashPair(left: bigint, right: bigint): bigint {
  return poseidon2([left, right]);
}

/**
 * Receiver check: does (v, ownerSelf, rseed) open expectedCm? A decrypted
 * plaintext is only a note if this holds (otherwise the sender lied in ct).
 */
export function noteMatches(v: bigint, ownerSelf: bigint, rseed: bigint, expectedCm: bigint): boolean {
  if (v < 0n || v > MAX_VALUE) return false;
  try {
    return cm(v, ownerSelf, rseed) === expectedCm;
  } catch {
    return false;
  }
}

// ---- Keys ----

export interface Keys {
  /** Spending secret; never leaves the wallet. */
  skSpend: bigint;
  /** Public owner tag committed in every note. */
  owner: bigint;
  /** Nullifier key, derived from skSpend. */
  skNf: bigint;
  /** X25519 secret key for note decryption (32 bytes). */
  skEnc: Uint8Array;
  /** X25519 public key (32 bytes). */
  pkEnc: Uint8Array;
}

/** X25519 public key of a 32-byte secret (RFC 7748 clamping applied by noble). */
export function pkEncOf(skEnc: Uint8Array): Uint8Array {
  if (skEnc.length !== 32) throw new RangeError('skEnc must be 32 bytes');
  return x25519.getPublicKey(skEnc);
}

/**
 * Deterministic keys from a wallet seed:
 *   sk_spend = HKDF-SHA256(seed, salt "zbtc/v1", info "spend", 64 bytes) mod R
 *   sk_enc   = HKDF-SHA256(seed, salt "zbtc/v1", info "enc",   32 bytes)
 */
export function keysFromSeed(seed: Uint8Array): Keys {
  if (seed.length < 16) throw new RangeError('seed must be at least 16 bytes');
  const salt = utf8ToBytes(KDF_SALT);
  const skSpend = modR(bytesToBigInt(hkdf(sha256, seed, salt, utf8ToBytes(KDF_INFO_SPEND), 64)));
  if (skSpend === 0n) throw new Error('degenerate sk_spend');
  const skEnc = hkdf(sha256, seed, salt, utf8ToBytes(KDF_INFO_ENC), 32);
  return { skSpend, owner: ownerOf(skSpend), skNf: skNfOf(skSpend), skEnc, pkEnc: pkEncOf(skEnc) };
}

// ---- Addresses ----

export interface Address {
  owner: bigint;
  pkEnc: Uint8Array;
}

const P25519 = (1n << 255n) - 19n;
const PROBE_SCALAR = new Uint8Array(32).fill(0x42);

/**
 * A usable X25519 public key: 32 bytes, canonical (u < 2^255 - 19, top bit
 * clear, as getPublicKey always produces) and not a low-order point (noble
 * rejects those in getSharedSecret).
 */
export function isValidPkEnc(pk: Uint8Array): boolean {
  if (pk.length !== EPK_BYTES) return false;
  if (bytesToBigInt(pk.slice().reverse()) >= P25519) return false;
  try {
    x25519.getSharedSecret(PROBE_SCALAR, pk);
    return true;
  } catch {
    return false;
  }
}

export function encodeAddress(a: Address): string {
  assertField(a.owner, 'owner');
  if (!isValidPkEnc(a.pkEnc)) throw new RangeError('invalid pkEnc');
  return ADDRESS_PREFIX + bytesToHex(bigIntToBytes(a.owner)) + bytesToHex(a.pkEnc);
}

const ADDRESS_BODY = /^[0-9a-f]+$/;

/** Strict inverse of encodeAddress: exact prefix and length, lowercase hex, owner < R, valid pkEnc. */
export function decodeAddress(s: string): Address {
  if (typeof s !== 'string' || !s.startsWith(ADDRESS_PREFIX)) throw new Error('address: bad prefix');
  if (s.length !== ADDRESS_LENGTH) throw new Error('address: bad length');
  const body = s.slice(ADDRESS_PREFIX.length);
  if (!ADDRESS_BODY.test(body)) throw new Error('address: not lowercase hex');
  const owner = bytesToBigInt(hexToBytes(body.slice(0, 2 * FIELD_BYTES)));
  if (!isField(owner)) throw new Error('address: owner >= r');
  const pkEnc = hexToBytes(body.slice(2 * FIELD_BYTES));
  if (!isValidPkEnc(pkEnc)) throw new Error('address: invalid pkEnc');
  return { owner, pkEnc };
}

// ---- Note encryption ----

export interface NotePlaintext {
  v: bigint;
  rseed: bigint;
}

export interface EncryptedNote {
  /** Ephemeral X25519 public key (32 bytes). */
  epk: Uint8Array;
  /** ChaCha20-Poly1305 ciphertext + tag (56 bytes). */
  ct: Uint8Array;
}

const ZERO_NONCE = new Uint8Array(12);

function noteKey(shared: Uint8Array, epk: Uint8Array, pkEnc: Uint8Array): Uint8Array {
  return hkdf(sha256, shared, utf8ToBytes(NOTE_KDF_SALT), concatBytes(epk, pkEnc), 32);
}

/**
 * Encrypts (v, rseed) to pkEnc, bound to cm through the AEAD aad.
 *   esk fresh; shared = X25519(esk, pkEnc); k = HKDF(shared, "zbtc/v1/note", epk || pkEnc)
 *   ct = ChaCha20-Poly1305(k, nonce = 0^12, aad = cm (32 B BE), v (u64 LE) || rseed (32 B BE))
 * A zero nonce is safe because every key is single-use (fresh esk per note).
 */
export function encryptNote(note: NotePlaintext, pkEnc: Uint8Array, noteCm: bigint): EncryptedNote {
  assertField(note.rseed, 'rseed');
  assertField(noteCm, 'cm');
  // The receiver derives k with its canonical pkEnc, so a non-canonical
  // encoding here would make the note undecryptable: refuse it.
  if (!isValidPkEnc(pkEnc)) throw new RangeError('invalid pkEnc');
  const pt = concatBytes(u64ToLe(note.v), bigIntToBytes(note.rseed));
  const { secretKey: esk, publicKey: epk } = x25519.keygen();
  const shared = x25519.getSharedSecret(esk, pkEnc);
  const k = noteKey(shared, epk, pkEnc);
  const ct = chacha20poly1305(k, ZERO_NONCE, bigIntToBytes(noteCm)).encrypt(pt);
  return { epk, ct };
}

/**
 * Trial decryption. Returns null (never throws) when the note is not ours or
 * malformed: wrong sizes, low-order epk (noble x25519 throws), AEAD failure
 * (wrong key, tampered ct/epk, wrong cm), plaintext != 40 B, or rseed >= r.
 * The caller must still check noteMatches(v, ownOwner, rseed, cm).
 */
export function decryptNote(
  skEnc: Uint8Array,
  epk: Uint8Array,
  ct: Uint8Array,
  noteCm: bigint,
): NotePlaintext | null {
  try {
    if (skEnc.length !== 32 || epk.length !== EPK_BYTES || ct.length !== CT_BYTES) return null;
    if (!isField(noteCm)) return null;
    const shared = x25519.getSharedSecret(skEnc, epk);
    const k = noteKey(shared, epk, pkEncOf(skEnc));
    const pt = chacha20poly1305(k, ZERO_NONCE, bigIntToBytes(noteCm)).decrypt(ct);
    if (pt.length !== NOTE_PLAINTEXT_BYTES) return null;
    const v = leToU64(pt.subarray(0, 8));
    const rseed = bytesToBigInt(pt.subarray(8, NOTE_PLAINTEXT_BYTES));
    if (!isField(rseed)) return null;
    return { v, rseed };
  } catch {
    return null;
  }
}

// ---- h_body ----

/**
 * h_body = first 31 bytes of SHA256(utf8("zbtc/v1/body") || body), big-endian.
 * 31 bytes keeps it below 2^248 < r, so it is always a canonical field element.
 */
export function hBody(body: Uint8Array): bigint {
  if (body.length !== BODY_BYTES) throw new RangeError(`body must be ${BODY_BYTES} bytes`);
  const digest = sha256(concatBytes(utf8ToBytes(H_BODY_DOMAIN), body));
  return bytesToBigInt(digest.subarray(0, H_BODY_BYTES));
}
