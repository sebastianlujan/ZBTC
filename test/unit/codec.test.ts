// Codec tests. Uses one real proved envelope (needs `pnpm circuit`).
import { readFileSync } from 'node:fs';
import { bn254 } from '@noble/curves/bn254.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  envelopeHBody,
  envelopeScript,
  extractEnvelope,
  parse,
  proofPointsError,
  serialize,
  serializeBody,
  type TxLike,
} from '../../src/codec.js';
import {
  BODY_BYTES,
  CIRCUITS,
  ENVELOPE_BYTES,
  OFF_CM,
  OFF_N_IN,
  OFF_N_OUT,
  OFF_NF,
  OFF_PROOF,
  OFF_TYPE,
  OFF_VERSION,
  Q,
  R,
} from '../../src/constants.js';
import { bigIntToBytes, bytesToHex, cm, hBody, randomField } from '../../src/crypto.js';
import { bytesToProof, dummyInput, publicSignalsOf, shutdownProver, verify } from '../../src/prover.js';
import { NoteTree } from '../../src/tree.js';
import { craftTransfer, type CraftedTransfer } from '../helpers/craft.js';
import { alice, bob } from '../helpers/fixtures.js';

let real: CraftedTransfer;
let bytes: Uint8Array;

beforeAll(async () => {
  const tree = new NoteTree();
  const rseed = randomField();
  const pos = tree.append(cm(100n, alice.owner, rseed));
  real = await craftTransfer({
    root: tree.root(),
    hAnchor: 123,
    skSpend: alice.skSpend,
    inputs: [{ v: 100n, rseed, pos, path: tree.witness(pos) }, dummyInput()],
    outputs: [
      { v: 30n, owner: bob.owner, pkEnc: bob.pkEnc },
      { v: 70n, owner: alice.owner, pkEnc: alice.pkEnc },
    ],
  });
  bytes = real.bytes;
});

afterAll(async () => {
  await shutdownProver();
});

function withBytes(at: number, patch: Uint8Array): Uint8Array {
  const b = bytes.slice();
  b.set(patch, at);
  return b;
}

function expectParseError(b: Uint8Array, reason?: RegExp): void {
  const r = parse(b);
  expect(r.ok).toBe(false);
  if (!r.ok) {
    expect(r.code).toBe('E_PARSE');
    if (reason) expect(r.reason).toMatch(reason);
  }
}

function txWith(...scriptsHex: string[]): TxLike {
  return { vout: scriptsHex.map((hex, n) => ({ n, scriptPubKey: { hex } })) };
}

const P2WPKH = '0014' + '11'.repeat(20);
const scriptHex = () => bytesToHex(envelopeScript(bytes));

describe('envelope serialization', () => {
  it('has the plan layout: 316-byte body, 572-byte envelope', () => {
    expect(bytes).toHaveLength(ENVELOPE_BYTES);
    expect(serializeBody(real.env)).toEqual(bytes.subarray(0, BODY_BYTES));
    expect(bytesToHex(bytes.subarray(0, 12))).toBe('7a627463' + '01' + '01' + '7b000000' + '02' + '02');
    expect(OFF_PROOF).toBe(316);
  });

  it('round-trips: parse(serialize(env)) == env and the proof verifies on recomputed h_body', async () => {
    const r = parse(bytes);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.env).toEqual(real.env);
    expect(serialize(r.env)).toEqual(bytes);
    const hb = hBody(bytes.subarray(0, BODY_BYTES));
    expect(hb).toBe(real.input.hBody);
    const signals = publicSignalsOf(real.input.root, hb, r.env.nf, r.env.cm);
    expect(await verify(signals, bytesToProof(r.env.proofBytes))).toBe(true);
  });

  it('length +-1 -> E_PARSE', () => {
    expectParseError(bytes.subarray(0, ENVELOPE_BYTES - 1), /length/);
    const longer = new Uint8Array(ENVELOPE_BYTES + 1);
    longer.set(bytes);
    expectParseError(longer, /length/);
    expectParseError(new Uint8Array(0), /length/);
  });

  it('each nf/cm slot set to r (or 2^256 - 1) -> E_PARSE', () => {
    for (const off of [OFF_NF, OFF_NF + 32, OFF_CM, OFF_CM + 32]) {
      expectParseError(withBytes(off, bigIntToBytes(R)), />= r/);
      expectParseError(withBytes(off, new Uint8Array(32).fill(0xff)), />= r/);
      // r - 1 is still canonical at the codec level.
      expect(parse(withBytes(off, bigIntToBytes(R - 1n))).ok).toBe(true);
    }
  });

  it('each proof coordinate set to q -> E_PARSE', () => {
    for (let i = 0; i < 8; i++) {
      expectParseError(withBytes(OFF_PROOF + 32 * i, bigIntToBytes(Q)), />= q/);
    }
  });

  it('bad magic, version, type or counts -> E_PARSE', () => {
    expectParseError(withBytes(0, new Uint8Array([0x7a, 0x62, 0x74, 0x64])), /magic/);
    expectParseError(withBytes(OFF_VERSION, new Uint8Array([2])), /version/);
    expectParseError(withBytes(OFF_VERSION, new Uint8Array([0])), /version/);
    expectParseError(withBytes(OFF_TYPE, new Uint8Array([2])), /type/);
    for (const n of [0, 1, 3, 255]) {
      expectParseError(withBytes(OFF_N_IN, new Uint8Array([n])), /counts/);
      expectParseError(withBytes(OFF_N_OUT, new Uint8Array([n])), /counts/);
    }
  });

  it('flipping any single body byte changes h_body, which stays < 2^248', () => {
    const body = bytes.slice(0, BODY_BYTES);
    const h0 = hBody(body);
    const seen = new Set<bigint>([h0]);
    for (let i = 0; i < BODY_BYTES; i++) {
      const b = body.slice();
      b[i] ^= 0x01;
      const h = hBody(b);
      expect(h).not.toBe(h0);
      expect(h < 1n << 248n).toBe(true);
      seen.add(h);
    }
    expect(seen.size).toBe(BODY_BYTES + 1);
    expect(envelopeHBody(real.env)).toBe(h0);
  });

  it('serializeBody refuses out-of-range fields', () => {
    expect(() => serializeBody({ ...real.env, hAnchor: -1 })).toThrow();
    expect(() => serializeBody({ ...real.env, hAnchor: 2 ** 32 })).toThrow();
    expect(() => serializeBody({ ...real.env, nf: [R, real.env.nf[1]] })).toThrow();
    expect(() => serializeBody({ ...real.env, epk: [new Uint8Array(31), real.env.epk[1]] })).toThrow();
    expect(() => serialize({ ...real.env, proofBytes: new Uint8Array(255) })).toThrow();
  });
});

describe('proof point validity (noble bn254)', () => {
  const G1 = bn254.G1.Point;
  const G2 = bn254.G2.Point;
  const toG1 = (a: string[]) => G1.fromAffine({ x: BigInt(a[0]), y: BigInt(a[1]) });
  const toG2 = (b: string[][]) =>
    G2.fromAffine({
      x: { c0: BigInt(b[0][0]), c1: BigInt(b[0][1]) },
      y: { c0: BigInt(b[1][0]), c1: BigInt(b[1][1]) },
    });

  it('a real proof passes, and noble verifies the Groth16 equation with the same mapping', () => {
    expect(proofPointsError(real.env.proofBytes)).toBeNull();

    // Independent Groth16 check in noble: e(-A,B) e(alpha,beta) e(vk_x,gamma) e(C,delta) == 1.
    // It only holds if snarkjs [c0, c1] maps to noble {c0, c1} for every G2 point.
    const vk = JSON.parse(readFileSync(CIRCUITS.main.vkey, 'utf8'));
    const p = real.proof;
    let vkx = toG1(vk.IC[0]);
    real.publicSignals.forEach((s, i) => {
      vkx = vkx.add(toG1(vk.IC[i + 1]).multiply(BigInt(s)));
    });
    const Fp12 = bn254.fields.Fp12;
    const gt = bn254.pairingBatch([
      { g1: toG1(p.pi_a).negate(), g2: toG2(p.pi_b) },
      { g1: toG1(vk.vk_alpha_1), g2: toG2(vk.vk_beta_2) },
      { g1: vkx, g2: toG2(vk.vk_gamma_2) },
      { g1: toG1(p.pi_c), g2: toG2(vk.vk_delta_2) },
    ]);
    expect(Fp12.eql(gt, Fp12.ONE)).toBe(true);
  });

  it('B with c0/c1 swapped is off the twist -> E_PARSE', () => {
    const pb = real.env.proofBytes;
    const sw = pb.slice();
    sw.set(pb.subarray(64, 96), 96);
    sw.set(pb.subarray(96, 128), 64);
    sw.set(pb.subarray(128, 160), 160);
    sw.set(pb.subarray(160, 192), 128);
    expectParseError(withBytes(OFF_PROOF, sw), /pi_b/);
  });

  it('B on the twist but outside the prime-order subgroup -> E_PARSE', () => {
    const Fp2 = bn254.fields.Fp2;
    const b = G2.CURVE().b;
    let off: InstanceType<typeof G2> | undefined;
    for (let i = 1n; i < 1000n && !off; i++) {
      const x = { c0: i, c1: 1n };
      let y;
      try {
        y = Fp2.sqrt(Fp2.add(Fp2.mul(Fp2.sqr(x), x), b));
      } catch {
        continue;
      }
      if (!y) continue;
      const P = G2.fromAffine({ x, y });
      if (!P.isTorsionFree()) off = P;
    }
    expect(off).toBeDefined();
    const { x, y } = off!.toAffine();
    // On the curve: only the subgroup check fails (snarkjs would accept it as well-formed).
    expect(Fp2.eql(Fp2.sqr(y), Fp2.add(Fp2.mul(Fp2.sqr(x), x), b))).toBe(true);
    expect(() => off!.assertValidity()).toThrow(/subgroup/);

    const coords = [x.c0, x.c1, y.c0, y.c1].map((c) => bigIntToBytes(c));
    const patched = bytes.slice();
    coords.forEach((c, i) => patched.set(c, OFF_PROOF + 64 + 32 * i));
    expectParseError(patched, /pi_b.*subgroup/);
  });

  it('infinity (0, 0) in A, B or C -> E_PARSE', () => {
    expectParseError(withBytes(OFF_PROOF, new Uint8Array(64)), /pi_a is the point at infinity/);
    expectParseError(withBytes(OFF_PROOF + 64, new Uint8Array(128)), /pi_b is the point at infinity/);
    expectParseError(withBytes(OFF_PROOF + 192, new Uint8Array(64)), /pi_c is the point at infinity/);
  });

  it('A or C off the curve -> E_PARSE', () => {
    const ay = BigInt(real.proof.pi_a[1]);
    expectParseError(withBytes(OFF_PROOF + 32, bigIntToBytes((ay + 1n) % Q)), /pi_a/);
    const cy = BigInt(real.proof.pi_c[1]);
    expectParseError(withBytes(OFF_PROOF + 224, bigIntToBytes((cy + 1n) % Q)), /pi_c/);
  });
});

describe('extractEnvelope', () => {
  it('finds the envelope behind 6a4d3c02 and returns the exact bytes and vout', () => {
    const r = extractEnvelope(txWith(P2WPKH, scriptHex()));
    expect(r.kind).toBe('envelope');
    if (r.kind === 'envelope') {
      expect(r.vout).toBe(1);
      expect(r.bytes).toEqual(bytes);
    }
    expect(scriptHex().startsWith('6a4d3c02')).toBe(true);
  });

  it('no OP_RETURN, an empty OP_RETURN, or wrong magic -> none', () => {
    expect(extractEnvelope(txWith(P2WPKH)).kind).toBe('none');
    expect(extractEnvelope(txWith('6a', P2WPKH)).kind).toBe('none');
    const wrongMagic = bytes.slice();
    wrongMagic[3] = 0x64; // "zbtd"
    expect(extractEnvelope(txWith(bytesToHex(envelopeScript(wrongMagic)))).kind).toBe('none');
    expect(extractEnvelope(txWith('6a0b68656c6c6f20776f726c64')).kind).toBe('none');
  });

  it('non-minimal push, wrong length or trailing opcodes -> E_PARSE', () => {
    const env = bytesToHex(bytes);
    const cases = [
      '6a4e3c020000' + env, // PUSHDATA4
      '6a4d3c02' + env + '51', // trailing OP_1
      '6a4d3b02' + env.slice(0, -2), // declares and carries 571 bytes
      '6a4d3c02' + env.slice(0, -2), // declares 572, carries 571
      '6a047a627463', // direct push of just the magic
      '6a4c047a627463', // PUSHDATA1 of just the magic
    ];
    for (const hex of cases) {
      const r = extractEnvelope(txWith(hex));
      expect(r, hex.slice(0, 16)).toMatchObject({ kind: 'reject', code: 'E_PARSE', vout: 0 });
    }
  });

  it('two magic OP_RETURNs -> E_MULTI (even if one is malformed)', () => {
    expect(extractEnvelope(txWith(scriptHex(), scriptHex()))).toEqual({ kind: 'reject', code: 'E_MULTI' });
    expect(extractEnvelope(txWith(scriptHex(), P2WPKH, '6a047a627463'))).toEqual({
      kind: 'reject',
      code: 'E_MULTI',
    });
  });

  it('one non-magic OP_RETURN plus one magic OP_RETURN parses fine', () => {
    const r = extractEnvelope(txWith('6a0b68656c6c6f20776f726c64', P2WPKH, scriptHex()));
    expect(r.kind).toBe('envelope');
    if (r.kind === 'envelope') {
      expect(r.vout).toBe(2);
      expect(parse(r.bytes).ok).toBe(true);
    }
  });
});
