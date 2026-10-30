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
/** Heads the envelope's associated data, so it cannot be mistaken for any other signed blob. */
export const ENVELOPE_AD_DOMAIN = 'zbtc/v2/envelope-ad';

// ---- Setup ----
/** Fixed width keeps seed ‖ tag unambiguous in the sampler and gives 256 bits of setup entropy. */
export const SETUP_SEED_BYTES = 32;
/** Domain tag for sampling mu, apart from the matrix randomness drawn from the same seed. */
export const MU_DOMAIN = 'zbtc/v2/mu';
/** A zero recovery cofactor has probability about 1/q per attempt, so a handful of retries is ample. */
export const MAX_SETUP_ATTEMPTS = 8;

// ---- Bitcoin ----
/** BIP340 secret keys are exactly 32 bytes; the envelope wraps them unchanged. */
export const SECRET_KEY_BYTES = 32;
/** A txid is a double SHA-256 digest. */
export const TXID_BYTES = 32;

// ---- Demo amounts (sats) ----
/** Paid to the recipient. The toy note's exit amount is this same value. */
export const PAYMENT_SATS = 100_000n;
/** Left to the miner; the spend has no change output. */
export const FEE_SATS = 1_000n;
/** The single funding output covers the payment and the fee exactly. */
export const FUNDING_SATS = PAYMENT_SATS + FEE_SATS;

// ---- Fixture ----
/** Bumped whenever the fixture's JSON shape changes, so an old file is rejected rather than misread. */
export const FIXTURE_VERSION = 1;
