// Canonical encoding of the 572-byte ZBTC envelope and its OP_RETURN carrier.
//
//   off  len  field
//     0    4  magic "zbtc"
//     4    1  version 0x01
//     5    1  type 0x01 (transfer)
//     6    4  h_anchor (u32 LE)
//    10    1  n_in = 2
//    11    1  n_out = 2
//    12   64  nf0, nf1          (32 B BE each, < r)
//    76   64  cm0, cm1          (32 B BE each, < r)
//   140   64  epk0, epk1        (X25519, opaque)
//   204  112  ct0, ct1          (ChaCha20-Poly1305, opaque)
//   316  256  proof             (see prover.proofToBytes)
//
// body = bytes[0, 316). parse() is canonical: every byte string it accepts
// re-serializes to itself, and anything else is E_PARSE.
import { bn254 } from '@noble/curves/bn254.js';
import {
  BODY_BYTES,
  CT_BYTES,
  ENVELOPE_BYTES,
  EPK_BYTES,
  FIELD_BYTES,
  MAGIC,
  N_IN,
  N_OUT,
  OFF_CM,
  OFF_CT,
  OFF_EPK,
  OFF_H_ANCHOR,
  OFF_MAGIC,
  OFF_N_IN,
  OFF_N_OUT,
  OFF_NF,
  OFF_PROOF,
  OFF_TYPE,
  OFF_VERSION,
  PROOF_BYTES,
  TYPE_TRANSFER,
  VERSION,
} from './constants.js';
import { bigIntToBytes, bytesToBigInt, hBody, hexToBytes, isField } from './crypto.js';
import { bytesToProof } from './prover.js';

export {
  BODY_BYTES,
  CT_BYTES,
  ENVELOPE_BYTES,
  EPK_BYTES,
  OFF_CM,
  OFF_CT,
  OFF_EPK,
  OFF_H_ANCHOR,
  OFF_MAGIC,
  OFF_N_IN,
  OFF_N_OUT,
  OFF_NF,
  OFF_PROOF,
  OFF_TYPE,
  OFF_VERSION,
  PROOF_BYTES,
};

/** OP_RETURN (0x6a) + OP_PUSHDATA2 (0x4d) + LE16(572) = 6a 4d 3c 02. */
export const SCRIPT_PREFIX = new Uint8Array([0x6a, 0x4d, ENVELOPE_BYTES & 0xff, ENVELOPE_BYTES >> 8]);
export const SCRIPT_BYTES = SCRIPT_PREFIX.length + ENVELOPE_BYTES; // 576

export interface Envelope {
  /** Anchor height (u32): the proof's root is R[hAnchor]. */
  hAnchor: number;
  nf: [bigint, bigint];
  cm: [bigint, bigint];
  /** Ephemeral X25519 public keys, 32 B each. */
  epk: [Uint8Array, Uint8Array];
  /** AEAD ciphertexts, 56 B each. */
  ct: [Uint8Array, Uint8Array];
  /** 256-byte proof (prover.proofToBytes layout). */
  proofBytes: Uint8Array;
}

export type ParseResult = { ok: true; env: Envelope } | { ok: false; code: 'E_PARSE'; reason: string };

// ---- Serialization ----

/** Writes the 316-byte body. Throws on any out-of-range field. */
export function serializeBody(env: Envelope): Uint8Array {
  if (!Number.isInteger(env.hAnchor) || env.hAnchor < 0 || env.hAnchor > 0xffffffff) {
    throw new RangeError('hAnchor must be a u32');
  }
  if (env.nf.length !== N_IN || env.cm.length !== N_OUT) throw new RangeError('wrong nf/cm count');
  if (env.epk.length !== N_OUT || env.ct.length !== N_OUT) throw new RangeError('wrong epk/ct count');

  const out = new Uint8Array(BODY_BYTES);
  out.set(MAGIC, OFF_MAGIC);
  out[OFF_VERSION] = VERSION;
  out[OFF_TYPE] = TYPE_TRANSFER;
  new DataView(out.buffer).setUint32(OFF_H_ANCHOR, env.hAnchor, true);
  out[OFF_N_IN] = N_IN;
  out[OFF_N_OUT] = N_OUT;
  writeFieldElements(out, OFF_NF, env.nf, 'nf');
  writeFieldElements(out, OFF_CM, env.cm, 'cm');
  writeChunks(out, OFF_EPK, env.epk, EPK_BYTES, 'epk');
  writeChunks(out, OFF_CT, env.ct, CT_BYTES, 'ct');
  return out;
}

/** Writes 32-byte big-endian field elements back to back; throws on any value >= r. */
function writeFieldElements(out: Uint8Array, offset: number, values: readonly bigint[], name: string): void {
  values.forEach((x, i) => {
    if (!isField(x)) throw new RangeError(`${name}[${i}] >= r`);
    out.set(bigIntToBytes(x), offset + i * FIELD_BYTES);
  });
}

/** Writes fixed-size opaque chunks back to back; throws on any chunk of the wrong size. */
function writeChunks(out: Uint8Array, offset: number, chunks: readonly Uint8Array[], size: number, name: string): void {
  chunks.forEach((b, i) => {
    if (b.length !== size) throw new RangeError(`${name}[${i}] must be ${size} bytes`);
    out.set(b, offset + i * size);
  });
}

/** Writes the full 572-byte envelope. */
export function serialize(env: Envelope): Uint8Array {
  if (env.proofBytes.length !== PROOF_BYTES) throw new RangeError(`proof must be ${PROOF_BYTES} bytes`);
  const out = new Uint8Array(ENVELOPE_BYTES);
  out.set(serializeBody(env), 0);
  out.set(env.proofBytes, OFF_PROOF);
  return out;
}

/** h_body of an envelope (recomputed from its canonical body). */
export function envelopeHBody(env: Envelope): bigint {
  return hBody(serializeBody(env));
}

/** OP_RETURN scriptPubKey carrying the envelope: 6a 4d 3c 02 || envelope. */
export function envelopeScript(bytes: Uint8Array): Uint8Array {
  if (bytes.length !== ENVELOPE_BYTES) throw new RangeError(`envelope must be ${ENVELOPE_BYTES} bytes`);
  const out = new Uint8Array(SCRIPT_BYTES);
  out.set(SCRIPT_PREFIX, 0);
  out.set(bytes, SCRIPT_PREFIX.length);
  return out;
}

// ---- Proof point validity ----
//
// snarkjs' verifier only checks that points are on the curve (and accepts the
// point at infinity). We additionally require A, C in G1 \ {O} and B in the
// prime-order G2 subgroup \ {O}. noble's bn254 is the EIP-196/197 curve, the
// same as snarkjs' bn128; its Fp2 element {c0, c1} = c0 + c1*u has the same
// component order as snarkjs' [c0, c1] (the EVM calldata order swaps them).

const { G1, G2 } = bn254;

function checkG1(x: bigint, y: bigint, what: string): string | null {
  try {
    const P = G1.Point.fromAffine({ x, y });
    if (P.is0()) return `${what} is the point at infinity`;
    P.assertValidity(); // on curve (G1 has cofactor 1)
    return null;
  } catch (e) {
    return `${what} invalid: ${(e as Error).message}`;
  }
}

function checkG2(xc0: bigint, xc1: bigint, yc0: bigint, yc1: bigint, what: string): string | null {
  try {
    const P = G2.Point.fromAffine({ x: { c0: xc0, c1: xc1 }, y: { c0: yc0, c1: yc1 } });
    if (P.is0()) return `${what} is the point at infinity`;
    P.assertValidity(); // on the twist AND in the prime-order subgroup
    return null;
  } catch (e) {
    return `${what} invalid: ${(e as Error).message}`;
  }
}

/**
 * Returns null if the 256-byte proof has every coordinate < q, A and C in
 * G1 \ {O}, and B in the G2 prime-order subgroup \ {O}; otherwise a reason.
 */
export function proofPointsError(proofBytes: Uint8Array): string | null {
  let p;
  try {
    p = bytesToProof(proofBytes); // length and coordinate < q checks
  } catch (e) {
    return (e as Error).message;
  }
  const n = (s: string) => BigInt(s);
  return (
    checkG1(n(p.pi_a[0]), n(p.pi_a[1]), 'pi_a') ??
    checkG2(n(p.pi_b[0][0]), n(p.pi_b[0][1]), n(p.pi_b[1][0]), n(p.pi_b[1][1]), 'pi_b') ??
    checkG1(n(p.pi_c[0]), n(p.pi_c[1]), 'pi_c')
  );
}

// ---- Parsing ----

function fail(reason: string): ParseResult {
  return { ok: false, code: 'E_PARSE', reason };
}

/** Canonical parse of a 572-byte envelope. Never throws. */
export function parse(bytes: Uint8Array): ParseResult {
  if (!(bytes instanceof Uint8Array)) return fail('not bytes');
  if (bytes.length !== ENVELOPE_BYTES) return fail(`length ${bytes.length} != ${ENVELOPE_BYTES}`);
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[OFF_MAGIC + i] !== MAGIC[i]) return fail('bad magic');
  }
  if (bytes[OFF_VERSION] !== VERSION) return fail(`bad version ${bytes[OFF_VERSION]}`);
  if (bytes[OFF_TYPE] !== TYPE_TRANSFER) return fail(`bad type ${bytes[OFF_TYPE]}`);
  if (bytes[OFF_N_IN] !== N_IN || bytes[OFF_N_OUT] !== N_OUT) {
    return fail(`bad counts ${bytes[OFF_N_IN]}/${bytes[OFF_N_OUT]}`);
  }

  const field = (off: number, what: string): bigint | string => {
    const x = bytesToBigInt(bytes.subarray(off, off + FIELD_BYTES));
    return isField(x) ? x : `${what} >= r`;
  };
  const nf0 = field(OFF_NF, 'nf[0]');
  const nf1 = field(OFF_NF + FIELD_BYTES, 'nf[1]');
  const cm0 = field(OFF_CM, 'cm[0]');
  const cm1 = field(OFF_CM + FIELD_BYTES, 'cm[1]');
  for (const x of [nf0, nf1, cm0, cm1]) if (typeof x === 'string') return fail(x);

  const proofBytes = bytes.slice(OFF_PROOF, OFF_PROOF + PROOF_BYTES);
  const proofErr = proofPointsError(proofBytes);
  if (proofErr) return fail(proofErr);

  const hAnchor = new DataView(bytes.buffer, bytes.byteOffset, bytes.length).getUint32(OFF_H_ANCHOR, true);
  return {
    ok: true,
    env: {
      hAnchor,
      nf: [nf0 as bigint, nf1 as bigint],
      cm: [cm0 as bigint, cm1 as bigint],
      epk: [bytes.slice(OFF_EPK, OFF_EPK + EPK_BYTES), bytes.slice(OFF_EPK + EPK_BYTES, OFF_EPK + 2 * EPK_BYTES)],
      ct: [bytes.slice(OFF_CT, OFF_CT + CT_BYTES), bytes.slice(OFF_CT + CT_BYTES, OFF_CT + 2 * CT_BYTES)],
      proofBytes,
    },
  };
}

// ---- Extraction from a bitcoind transaction ----

/** The subset of `getblock <hash> 2` transaction JSON that extraction needs. */
export interface TxVoutLike {
  n?: number;
  scriptPubKey: { hex: string };
}
export interface TxLike {
  vout: TxVoutLike[];
}

export type Extracted =
  | { kind: 'none' }
  | { kind: 'envelope'; bytes: Uint8Array; vout: number }
  | { kind: 'reject'; code: 'E_PARSE' | 'E_MULTI'; vout?: number };

/**
 * Data of the first push after OP_RETURN (possibly truncated if the script is
 * malformed), or null if the first opcode is not a data push.
 */
function firstPushData(script: Uint8Array): Uint8Array | null {
  if (script.length < 2 || script[0] !== 0x6a) return null;
  const op = script[1];
  let len: number;
  let start: number;
  if (op >= 0x01 && op <= 0x4b) {
    len = op;
    start = 2;
  } else if (op === 0x4c) {
    if (script.length < 3) return null;
    len = script[2];
    start = 3;
  } else if (op === 0x4d) {
    if (script.length < 4) return null;
    len = script[2] | (script[3] << 8);
    start = 4;
  } else if (op === 0x4e) {
    if (script.length < 6) return null;
    len = (script[2] | (script[3] << 8) | (script[4] << 16) | (script[5] << 24)) >>> 0;
    start = 6;
  } else {
    return null;
  }
  return script.subarray(start, Math.min(start + len, script.length));
}

function startsWithMagic(data: Uint8Array): boolean {
  return data.length >= MAGIC.length && MAGIC.every((b, i) => data[i] === b);
}

/**
 * Finds the ZBTC envelope in a transaction.
 *   - candidate: an OP_RETURN output whose first pushed data starts with "zbtc";
 *   - no candidate -> none (non-magic OP_RETURNs are ignored);
 *   - more than one candidate -> E_MULTI;
 *   - the candidate script must be exactly 6a 4d 3c 02 || 572 bytes (minimal
 *     PUSHDATA2, nothing after it), otherwise E_PARSE.
 */
export function extractEnvelope(tx: TxLike): Extracted {
  const candidates: { vout: number; script: Uint8Array }[] = [];
  tx.vout.forEach((out, idx) => {
    const hex = out.scriptPubKey?.hex;
    if (typeof hex !== 'string' || !hex.startsWith('6a')) return;
    let script: Uint8Array;
    try {
      script = hexToBytes(hex);
    } catch {
      return;
    }
    const data = firstPushData(script);
    if (data && startsWithMagic(data)) candidates.push({ vout: out.n ?? idx, script });
  });

  if (candidates.length === 0) return { kind: 'none' };
  if (candidates.length > 1) return { kind: 'reject', code: 'E_MULTI' };

  const { vout, script } = candidates[0];
  const exact =
    script.length === SCRIPT_BYTES && SCRIPT_PREFIX.every((b, i) => script[i] === b);
  if (!exact) return { kind: 'reject', code: 'E_PARSE', vout };
  return { kind: 'envelope', bytes: script.slice(SCRIPT_PREFIX.length), vout };
}
