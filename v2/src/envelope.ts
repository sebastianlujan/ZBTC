// Wraps secret bytes (from M2 on, a Bitcoin private key) under a key derived
// from the AADP secret mu.
//
// seal:   K = HKDF-SHA256(ikm = mu as 32-byte big-endian, salt, info, 32 bytes)
//         ciphertext = XChaCha20-Poly1305(K, random 24-byte nonce, associatedData).encrypt(plaintext)
// unseal: re-derive K from a recovered candidate mu and decrypt. The AEAD tag
//         is what authenticates the candidate: a wrong mu, nonce, ciphertext
//         or associated data all fail the same way, with null.
//
// The plaintext is opaque bytes and is never reduced mod q, so every 32-byte
// key round-trips unchanged, including keys that start with 0x00.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  ENVELOPE_KDF_INFO,
  ENVELOPE_KDF_SALT,
  ENVELOPE_KEY_BYTES,
  ENVELOPE_NONCE_BYTES,
} from './constants.js';
import { encodeFieldElement } from './field.js';

export interface SealedEnvelope {
  readonly nonce: Uint8Array;
  /** AEAD ciphertext followed by its Poly1305 tag. */
  readonly ciphertext: Uint8Array;
}

/** The fixed-width encoding makes K a function of mu alone, not of how many leading zeros mu has. */
function envelopeKey(mu: bigint): Uint8Array {
  return hkdf(
    sha256,
    encodeFieldElement(mu),
    utf8ToBytes(ENVELOPE_KDF_SALT),
    utf8ToBytes(ENVELOPE_KDF_INFO),
    ENVELOPE_KEY_BYTES,
  );
}

/** Throws RangeError when mu is not a canonical element of F_q. */
export function seal(mu: bigint, plaintext: Uint8Array, associatedData: Uint8Array): SealedEnvelope {
  const key = envelopeKey(mu);
  const nonce = randomBytes(ENVELOPE_NONCE_BYTES);
  const ciphertext = xchacha20poly1305(key, nonce, associatedData).encrypt(plaintext);
  return { nonce, ciphertext };
}

/** The plaintext, or null (never throws) for a wrong mu, a malformed envelope or any tampering. */
export function unseal(
  mu: bigint,
  sealed: SealedEnvelope,
  associatedData: Uint8Array,
): Uint8Array | null {
  try {
    if (sealed.nonce.length !== ENVELOPE_NONCE_BYTES) return null;
    const key = envelopeKey(mu);
    return xchacha20poly1305(key, sealed.nonce, associatedData).decrypt(sealed.ciphertext);
  } catch {
    return null;
  }
}
