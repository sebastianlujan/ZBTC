// Builds real ZBTC envelopes for tests (valid statement, real encryption, real
// h_body, real Groth16 proof) and byte-level mutators for adversarial cases.
import { bn254 } from '@noble/curves/bn254.js';
import { randomBytes } from '@noble/hashes/utils.js';
import {
  OFF_CM,
  OFF_CT,
  OFF_EPK,
  OFF_H_ANCHOR,
  OFF_NF,
  OFF_PROOF,
  parse,
  serialize,
  type Envelope,
  envelopeHBody,
} from '../../src/codec.js';
import { MAX_VALUE, PROOF_BYTES, R, type CircuitName } from '../../src/constants.js';
import { bigIntToBytes, bytesToBigInt, encryptNote, randomField } from '../../src/crypto.js';
import {
  buildCircuitInput,
  proofToBytes,
  prove,
  publicSignalsOf,
  type CircuitInput,
  type Groth16Proof,
  type PublicSignals,
  type SpendNote,
} from '../../src/prover.js';
import { buildEnvelopeTx, type BitcoinRpc, type EnvelopeTx } from '../../src/rpc.js';

// ---- Real envelopes ----

export interface CraftOutput {
  v: bigint;
  owner: bigint;
  pkEnc: Uint8Array;
  rseed?: bigint;
}

export interface CraftOptions {
  root: bigint;
  hAnchor: number;
  skSpend: bigint;
  inputs: [SpendNote, SpendNote];
  outputs: [CraftOutput, CraftOutput];
  circuit?: CircuitName;
}

export interface CraftedTransfer {
  env: Envelope;
  bytes: Uint8Array;
  input: CircuitInput;
  proof: Groth16Proof;
  publicSignals: PublicSignals;
  /** rseed of each output, for the receiver-side assertions. */
  outRseed: [bigint, bigint];
}

/**
 * Proves a transfer. Outputs whose value does not fit in 64 bits (only
 * provable on the unsafe norange circuit) get random epk/ct: there is no
 * plaintext encoding for them.
 */
export async function craftTransfer(o: CraftOptions): Promise<CraftedTransfer> {
  const outs = o.outputs.map((x) => ({ ...x, rseed: x.rseed ?? randomField() }));
  const input = buildCircuitInput({
    root: o.root,
    hBody: 0n, // placeholder: h_body depends on the body, which depends on nf/cm
    skSpend: o.skSpend,
    inputs: o.inputs,
    outputs: outs.map(({ v, owner, rseed }) => ({ v, owner, rseed })),
  });
  const enc = outs.map((x, k) =>
    x.v <= MAX_VALUE
      ? encryptNote({ v: x.v, rseed: x.rseed }, x.pkEnc, input.cm[k])
      : { epk: randomBytes(32), ct: randomBytes(56) },
  );
  const env: Envelope = {
    hAnchor: o.hAnchor,
    nf: [input.nf[0], input.nf[1]],
    cm: [input.cm[0], input.cm[1]],
    epk: [enc[0].epk, enc[1].epk],
    ct: [enc[0].ct, enc[1].ct],
    proofBytes: new Uint8Array(PROOF_BYTES),
  };
  input.hBody = envelopeHBody(env);
  const { proof, publicSignals } = await prove(input, o.circuit ?? 'main');
  if (publicSignals.join() !== publicSignalsOf(input.root, input.hBody, input.nf, input.cm).join()) {
    throw new Error('public signal order mismatch');
  }
  env.proofBytes = proofToBytes(proof);
  return { env, bytes: serialize(env), input, proof, publicSignals, outRseed: [outs[0].rseed, outs[1].rseed] };
}

// ---- Byte-level mutators (all return a copy) ----

export type Region = 'anchor' | 'nf' | 'cm' | 'epk' | 'ct' | 'proof';

/**
 * Default byte flipped per region:
 *   anchor: LSB of the u32 LE height (h -> h ^ 1);
 *   nf, cm: LSB of the first 32-byte big-endian element (value +-1, stays < r);
 *   epk, ct: first byte of the first element;
 *   proof: LSB of A.x (A leaves the curve -> E_PARSE, not E_PROOF).
 */
const DEFAULT_BYTE: Record<Region, number> = {
  anchor: OFF_H_ANCHOR,
  nf: OFF_NF + 31,
  cm: OFF_CM + 31,
  epk: OFF_EPK,
  ct: OFF_CT,
  proof: OFF_PROOF + 31,
};

export function flipByte(bytes: Uint8Array, region: Region, at: number = DEFAULT_BYTE[region]): Uint8Array {
  const b = bytes.slice();
  b[at] ^= 0x01;
  return b;
}

/** Parses, lets `fn` edit the envelope, re-serializes (canonical edits only). */
export function mutateEnv(bytes: Uint8Array, fn: (env: Envelope) => void): Uint8Array {
  const r = parse(bytes);
  if (!r.ok) throw new Error(`mutateEnv: input does not parse (${r.reason})`);
  const env: Envelope = {
    ...r.env,
    nf: [...r.env.nf],
    cm: [...r.env.cm],
    epk: [r.env.epk[0].slice(), r.env.epk[1].slice()],
    ct: [r.env.ct[0].slice(), r.env.ct[1].slice()],
    proofBytes: r.env.proofBytes.slice(),
  };
  fn(env);
  return serialize(env);
}

export function setCm(bytes: Uint8Array, k: 0 | 1, cm: bigint): Uint8Array {
  return mutateEnv(bytes, (e) => {
    e.cm[k] = cm;
  });
}

export function setNfsEqual(bytes: Uint8Array): Uint8Array {
  return mutateEnv(bytes, (e) => {
    e.nf[1] = e.nf[0];
  });
}

export function withProofBytes(bytes: Uint8Array, proofBytes: Uint8Array): Uint8Array {
  const b = bytes.slice();
  b.set(proofBytes, OFF_PROOF);
  return b;
}

/**
 * nf[k] + r written as 32 bytes (still < 2^256): the same residue mod r but a
 * non-canonical encoding, which the codec must reject (E_PARSE).
 */
export function aliasNf(bytes: Uint8Array, k: 0 | 1 = 0): Uint8Array {
  const off = OFF_NF + 32 * k;
  const nf = bytesToBigInt(bytes.subarray(off, off + 32));
  const b = bytes.slice();
  b.set(bigIntToBytes(nf + R), off);
  return b;
}

function randomScalar(): bigint {
  for (;;) {
    const s = randomField();
    if (s !== 0n) return s;
  }
}

/**
 * Well-formed but meaningless proof: A, C random multiples of the G1
 * generator, B a random multiple of the G2 generator. Every point is valid
 * and in its subgroup, so parse succeeds and the failure is E_PROOF.
 */
export function randomValidProofBytes(): Uint8Array {
  const A = bn254.G1.Point.BASE.multiply(randomScalar()).toAffine();
  const B = bn254.G2.Point.BASE.multiply(randomScalar()).toAffine();
  const C = bn254.G1.Point.BASE.multiply(randomScalar()).toAffine();
  const out = new Uint8Array(PROOF_BYTES);
  [A.x, A.y, B.x.c0, B.x.c1, B.y.c0, B.y.c1, C.x, C.y].forEach((c, i) => out.set(bigIntToBytes(c), 32 * i));
  return out;
}

/** Coordinates < q but not curve points: must fail at parse time (E_PARSE). */
export function offCurveProofBytes(): Uint8Array {
  const out = new Uint8Array(PROOF_BYTES);
  for (let i = 0; i < 8; i++) out.set(bigIntToBytes(BigInt(i + 1)), 32 * i);
  return out;
}

/** Puts (possibly mutated) envelope bytes into a fresh signed carrier from `feeWallet` (not sent). */
export function rewrap(rpc: BitcoinRpc, feeWallet: string, bytes: Uint8Array): Promise<EnvelopeTx> {
  return buildEnvelopeTx(rpc, feeWallet, bytes);
}
