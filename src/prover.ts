// Groth16 proving / verification for the Transfer circuit, plus the 256-byte
// proof encoding used in the envelope.
import { readFileSync } from 'node:fs';
import * as snarkjs from 'snarkjs';
import type { Groth16Proof, PublicSignals, VerificationKey } from 'snarkjs';
import { CIRCUITS, DEPTH, FIELD_BYTES, N_IN, N_OUT, PROOF_BYTES, Q, type CircuitName } from './constants.js';
import { bigIntToBytes, bytesToBigInt, cm as noteCm, nf as noteNf, randomField, skNfOf } from './crypto.js';

export type { Groth16Proof, PublicSignals, VerificationKey } from 'snarkjs';

/** An input note being spent (or a zero-value dummy). */
export interface SpendNote {
  v: bigint;
  rseed: bigint;
  pos: number | bigint;
  /** Siblings, leaf level first; DEPTH elements. */
  path: readonly bigint[];
}

/** A new output note. */
export interface OutputNote {
  v: bigint;
  owner: bigint;
  rseed: bigint;
}

export interface TransferParams {
  root: bigint;
  hBody: bigint;
  skSpend: bigint;
  inputs: readonly SpendNote[];
  outputs: readonly OutputNote[];
}

/** Circuit input, keyed by the exact signal names of Transfer(2,2,20,*,*). */
export interface CircuitInput {
  // public
  root: bigint;
  hBody: bigint;
  nf: bigint[];
  cm: bigint[];
  // private
  skSpend: bigint;
  inV: bigint[];
  inRseed: bigint[];
  inPos: bigint[];
  inPath: bigint[][];
  outV: bigint[];
  outOwner: bigint[];
  outRseed: bigint[];
}

/**
 * Zero-value dummy input: v = 0, fresh random rseed (so its nullifier is
 * unique), pos = 0, all-zero path. The circuit skips membership when v = 0.
 */
export function dummyInput(): SpendNote {
  return { v: 0n, rseed: randomField(), pos: 0, path: new Array<bigint>(DEPTH).fill(0n) };
}

/**
 * Maps a transfer to circuit signals, deriving the public nf[] and cm[] from
 * the private data. It does NOT check that the statement holds (balance,
 * ranges, membership): the circuit does, and callers must verify locally.
 */
export function buildCircuitInput(p: TransferParams): CircuitInput {
  if (p.inputs.length !== N_IN) throw new RangeError(`expected ${N_IN} inputs`);
  if (p.outputs.length !== N_OUT) throw new RangeError(`expected ${N_OUT} outputs`);
  for (const i of p.inputs) {
    if (i.path.length !== DEPTH) throw new RangeError(`input path must have ${DEPTH} elements`);
  }
  const skNf = skNfOf(p.skSpend);
  return {
    root: p.root,
    hBody: p.hBody,
    nf: p.inputs.map((i) => noteNf(skNf, i.rseed, i.pos)),
    cm: p.outputs.map((o) => noteCm(o.v, o.owner, o.rseed)),
    skSpend: p.skSpend,
    inV: p.inputs.map((i) => i.v),
    inRseed: p.inputs.map((i) => i.rseed),
    inPos: p.inputs.map((i) => BigInt(i.pos)),
    inPath: p.inputs.map((i) => [...i.path]),
    outV: p.outputs.map((o) => o.v),
    outOwner: p.outputs.map((o) => o.owner),
    outRseed: p.outputs.map((o) => o.rseed),
  };
}

/** Public signals in circuit order: [root, hBody, nf0, nf1, cm0, cm1]. */
export function publicSignalsOf(
  root: bigint,
  hBody: bigint,
  nf: readonly bigint[],
  cm: readonly bigint[],
): PublicSignals {
  if (nf.length !== N_IN || cm.length !== N_OUT) throw new RangeError('wrong nf/cm count');
  return [root, hBody, ...nf, ...cm].map((x) => x.toString(10));
}

function toSnarkInput(input: CircuitInput): Record<string, unknown> {
  const dec = (x: unknown): unknown => (Array.isArray(x) ? x.map(dec) : (x as bigint).toString(10));
  return Object.fromEntries(Object.entries(input).map(([k, v]) => [k, dec(v)]));
}

/**
 * Computes the witness and a Groth16 proof. Throws if the witness does not
 * satisfy the circuit (snarkjs reports the failing template).
 */
export async function prove(
  input: CircuitInput,
  circuit: CircuitName = 'main',
): Promise<{ proof: Groth16Proof; publicSignals: PublicSignals }> {
  const a = CIRCUITS[circuit];
  return snarkjs.groth16.fullProve(toSnarkInput(input), a.wasm, a.zkey);
}

const vkeyCache = new Map<CircuitName, VerificationKey>();

export function loadVkey(circuit: CircuitName = 'main'): VerificationKey {
  let vk = vkeyCache.get(circuit);
  if (!vk) {
    vk = JSON.parse(readFileSync(CIRCUITS[circuit].vkey, 'utf8')) as VerificationKey;
    vkeyCache.set(circuit, vk);
  }
  return vk;
}

const DECIMAL = /^(0|[1-9][0-9]*)$/;

/**
 * Groth16 verification. Returns false (never throws) on a bad proof, a wrong
 * number of public signals, a non-canonical decimal, or a signal >= r
 * (snarkjs >= 0.7 rejects those; CVE-2023-33252).
 */
export async function verify(
  publicSignals: PublicSignals,
  proof: Groth16Proof,
  circuit: CircuitName = 'main',
): Promise<boolean> {
  try {
    return await verifyWithVkey(loadVkey(circuit), publicSignals, proof);
  } catch {
    return false;
  }
}

/** Same as verify(), against an explicit verification key. Never throws. */
export async function verifyWithVkey(
  vk: VerificationKey,
  publicSignals: PublicSignals,
  proof: Groth16Proof,
): Promise<boolean> {
  try {
    if (publicSignals.length !== vk.nPublic) return false;
    if (!publicSignals.every((s) => typeof s === 'string' && DECIMAL.test(s))) return false;
    return await snarkjs.groth16.verify(vk, publicSignals, proof);
  } catch {
    return false;
  }
}

// ---- 256-byte proof encoding ----
//
// Layout: A.x, A.y, B.x.c0, B.x.c1, B.y.c0, B.y.c1, C.x, C.y; each a 32-byte
// big-endian F_q element. This follows the snarkjs JSON order for pi_b
// (pi_b[i] = [c0, c1]); it is NOT the EVM precompile order, which swaps c0/c1.
// Points are affine, so the projective z is implicit ("1" / ["1", "0"]).

function coord(s: string): bigint {
  if (!DECIMAL.test(s)) throw new Error('proof coordinate is not a decimal string');
  const x = BigInt(s);
  if (x >= Q) throw new RangeError('proof coordinate >= q');
  return x;
}

export function proofToBytes(proof: Groth16Proof): Uint8Array {
  const { pi_a: a, pi_b: b, pi_c: c } = proof;
  if (a[2] !== '1' || c[2] !== '1' || b[2][0] !== '1' || b[2][1] !== '0') {
    throw new Error('proof points must be affine (z = 1)');
  }
  const coords = [a[0], a[1], b[0][0], b[0][1], b[1][0], b[1][1], c[0], c[1]].map(coord);
  const out = new Uint8Array(PROOF_BYTES);
  coords.forEach((x, i) => out.set(bigIntToBytes(x, FIELD_BYTES), i * FIELD_BYTES));
  return out;
}

/** Inverse of proofToBytes. Throws on wrong length or any coordinate >= q. */
export function bytesToProof(bytes: Uint8Array): Groth16Proof {
  if (bytes.length !== PROOF_BYTES) throw new RangeError(`proof must be ${PROOF_BYTES} bytes`);
  const c: string[] = [];
  for (let i = 0; i < 8; i++) {
    const x = bytesToBigInt(bytes.subarray(i * FIELD_BYTES, (i + 1) * FIELD_BYTES));
    if (x >= Q) throw new RangeError('proof coordinate >= q');
    c.push(x.toString(10));
  }
  return {
    pi_a: [c[0], c[1], '1'],
    pi_b: [
      [c[2], c[3]],
      [c[4], c[5]],
      ['1', '0'],
    ],
    pi_c: [c[6], c[7], '1'],
    protocol: 'groth16',
    curve: 'bn128',
  };
}

/**
 * Terminates the snarkjs/ffjavascript worker threads so the process can exit.
 * ffjavascript caches one multi-threaded BN254 curve in globalThis.curve_bn128;
 * its terminate() posts TERMINATE to every worker and clears the cache, so a
 * later prove/verify transparently rebuilds it.
 */
export async function shutdownProver(): Promise<void> {
  const g = globalThis as { curve_bn128?: { terminate?: () => Promise<void> } | null };
  const curve = g.curve_bn128;
  if (curve && typeof curve.terminate === 'function') await curve.terminate();
}
