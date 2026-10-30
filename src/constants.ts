// Protocol constants for ZBTC v1. Domain tags, sizes and offsets here are
// consensus-relevant for every client that replays the chain: changing any of
// them forks the shielded state.
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// ---- Envelope identity ----
/** ASCII "zbtc". */
export const MAGIC = new Uint8Array([0x7a, 0x62, 0x74, 0x63]);
export const VERSION = 0x01;
export const TYPE_TRANSFER = 0x01;

// ---- Poseidon domain tags (must match circuits/transfer_template.circom) ----
export const DOM_OWN = 1n;
export const DOM_NFK = 2n;
export const DOM_CM = 3n;
export const DOM_NF = 4n;

// ---- Circuit / protocol parameters ----
/** Merkle tree height: at most 2^20 notes. */
export const DEPTH = 20;
/** Anchor window: h_anchor must lie in [max(S-1, H-W), H-1]. */
export const W = 100;
/** Confirmations before a received note is spendable. */
export const K_MIN = 1;
/** Every value is range-checked to this many bits in the circuit. */
export const VALUE_BITS = 64;
export const N_IN = 2;
export const N_OUT = 2;
export const MAX_VALUE = (1n << BigInt(VALUE_BITS)) - 1n;
export const MAX_LEAVES = 1 << DEPTH;

// ---- BN254 ----
/** Scalar field order r: every circuit signal / public input lives in F_r. */
export const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** Base field order q: every proof coordinate lives in F_q. */
export const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// ---- Envelope layout (572 bytes, single OP_RETURN with PUSHDATA2) ----
export const FIELD_BYTES = 32;
export const PROOF_BYTES = 256;
export const EPK_BYTES = 32;
/** AEAD plaintext: v (8 bytes) || rseed (32 bytes). Exact encoding is fixed in the codec (M2). */
export const NOTE_PLAINTEXT_BYTES = 40;
export const AEAD_TAG_BYTES = 16;
export const CT_BYTES = NOTE_PLAINTEXT_BYTES + AEAD_TAG_BYTES; // 56

export const OFF_MAGIC = 0;
export const OFF_VERSION = 4;
export const OFF_TYPE = 5;
export const OFF_H_ANCHOR = 6; // u32 LE
export const OFF_N_IN = 10;
export const OFF_N_OUT = 11;
export const OFF_NF = 12; // N_IN * 32
export const OFF_CM = OFF_NF + N_IN * FIELD_BYTES; // 76
export const OFF_EPK = OFF_CM + N_OUT * FIELD_BYTES; // 140
export const OFF_CT = OFF_EPK + N_OUT * EPK_BYTES; // 204
export const OFF_PROOF = OFF_CT + N_OUT * CT_BYTES; // 316
/** body = envelope[0, BODY_BYTES): everything except the proof. */
export const BODY_BYTES = OFF_PROOF; // 316
export const ENVELOPE_BYTES = OFF_PROOF + PROOF_BYTES; // 572

/** h_body = first 31 bytes of SHA256(H_BODY_DOMAIN || body), big-endian. */
export const H_BODY_DOMAIN = 'zbtc/v1/body';
export const H_BODY_BYTES = 31;

// ---- Key derivation ----
export const KDF_SALT = 'zbtc/v1';
export const KDF_INFO_SPEND = 'spend';
export const KDF_INFO_ENC = 'enc';
/** HKDF salt for the per-note AEAD key: k = HKDF(shared, salt, epk || pkEnc, 32). */
export const NOTE_KDF_SALT = 'zbtc/v1/note';

// ---- Address: "zbtcrt" + hex(owner, 32 B BE) + hex(pkEnc, 32 B) ----
export const ADDRESS_PREFIX = 'zbtcrt';
export const ADDRESS_LENGTH = ADDRESS_PREFIX.length + 2 * (FIELD_BYTES + EPK_BYTES); // 134

// ---- Build artifacts ----
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const BUILD_DIR = path.join(REPO_ROOT, 'build');

/**
 * 'main' is the production statement. 'norange' and 'nosquare' are UNSAFE
 * test-only variants (see circuits/variants/).
 */
export type CircuitName = 'main' | 'norange' | 'nosquare';

export interface CircuitArtifacts {
  r1cs: string;
  wasm: string;
  zkey: string;
  vkey: string;
}

function artifactsFor(base: string): CircuitArtifacts {
  const dir = path.join(BUILD_DIR, base);
  return {
    r1cs: path.join(dir, `${base}.r1cs`),
    wasm: path.join(dir, `${base}_js`, `${base}.wasm`),
    zkey: path.join(dir, `${base}.zkey`),
    vkey: path.join(dir, 'vkey.json'),
  };
}

export const CIRCUITS: Record<CircuitName, CircuitArtifacts> = {
  main: artifactsFor('transfer'),
  norange: artifactsFor('norange'),
  nosquare: artifactsFor('nosquare'),
};
