// Protocol constants for ZBTC v2. The field, block shape, sampler layout and
// domain tags fix how a setup seed expands into matrices and how mu becomes an
// envelope key: changing any of them makes earlier ciphertexts and envelopes
// unrecoverable.

// ---- BN254 base field ----
/** Base field order q of BN254. The AADP spec (R01) works over q, not the scalar field r. */
export const BASE_FIELD_MODULUS =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;
/** Canonical fixed-width big-endian encoding of one element of F_q (q < 2^256). */
export const FIELD_ELEMENT_BYTES = 32;

// ---- AADP shape ----
/** Side of each constraint's U block (Algorithm 1): two 2×2 blocks plus the xi coupling. */
export const AADP_BLOCK_SIZE = 4;
/** A satisfied constraint's U block has rank at most 2, so k = 2m + 1 leaves one spare dimension for mu. */
export const SATISFIED_BLOCK_RANK = 2;

// ---- Deterministic setup sampler ----
/** Domain tag separating AADP setup randomness from any other use of the same seed. */
export const AADP_SETUP_DOMAIN = 'zbtc/v2/aadp-setup';
/** The sampler counter is a u32, so one seed and tag yield at most 2^32 hash blocks. */
export const SAMPLER_COUNTER_BYTES = 4;

// ---- Envelope ----
/** XChaCha20-Poly1305 key length. */
export const ENVELOPE_KEY_BYTES = 32;
/** XChaCha20's 24-byte nonce is large enough to pick at random without a counter. */
export const ENVELOPE_NONCE_BYTES = 24;
/** HKDF salt: separates the envelope key from every other key derived from mu. */
export const ENVELOPE_KDF_SALT = 'zbtc/v2/envelope';
/** HKDF info: names the one key this derivation produces. */
export const ENVELOPE_KDF_INFO = 'zbtc/v2/envelope/aead-key';
