// Soundness and malleability on a real chain. Every forged or mutated
// envelope is put in its own carrier from a separate fee coin and mined with
// generateblock, so the outcome depends only on the shielded rules.
import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { extractEnvelope, parse } from '../../src/codec.js';
import { CIRCUITS, R } from '../../src/constants.js';
import { cm as noteCm, encryptNote, randomField } from '../../src/crypto.js';
import type { Replay } from '../../src/indexer.js';
import {
  buildCircuitInput,
  bytesToProof,
  dummyInput,
  proofToBytes,
  prove,
  shutdownProver,
  verify,
  type VerificationKey,
} from '../../src/prover.js';
import type { TransferHooks, TransferResult } from '../../src/wallet.js';
import {
  aliasNf,
  craftTransfer,
  flipByte,
  mutateEnv,
  offCurveProofBytes,
  randomValidProofBytes,
  rewrap,
  withProofBytes,
  type Region,
} from '../helpers/craft.js';
import { rerandomize } from '../helpers/rerandomize.js';
import { makeWorld, type World } from '../helpers/world.js';

const NOTES = 12;
const SUPPLY = 100n * BigInt(NOTES);
const vk = JSON.parse(readFileSync(CIRCUITS.main.vkey, 'utf8')) as VerificationKey;

let w: World;
/** Value made undetectable on purpose (garbage ciphertext, case g). */
let lost = 0n;

function outcome(r: Replay, txid: string): string {
  if (r.accepted.some((a) => a.txid === txid)) return 'acc';
  return r.rejected.find((x) => x.txid === txid)?.code ?? 'absent';
}

async function aliceSends(
  to: string,
  amount: bigint,
  hooks?: TransferHooks,
  feeWallet = 'alice-fee',
): Promise<TransferResult> {
  return w.wallets.alice.buildTransfer({
    replay: await w.replay(),
    rpc: w.node.rpc,
    to: w.wallets[to].address(),
    amount,
    feeWallet,
    hooks,
  });
}

async function mempoolEnvelope(txid: string): Promise<Uint8Array> {
  const ex = extractEnvelope(await w.node.rpc.getRawTransaction(txid, true));
  if (ex.kind !== 'envelope') throw new Error('no envelope in mempool tx');
  return ex.bytes;
}

async function expectSupply(): Promise<void> {
  expect((await w.detectedSupply()).total).toBe(SUPPLY - lost);
}

beforeAll(async () => {
  w = await makeWorld({
    actors: ['alice', 'bob', 'carol', 'mallory'],
    genesis: { alice: Array.from({ length: NOTES }, () => 100n) },
    feeUtxos: 20,
  });
  // Two empty blocks: R[S-1] = R[S] = R[S+1] (needed by case d's anchor flip).
  await w.mine(2);
});

afterAll(async () => {
  await w?.stop();
  await shutdownProver();
});

describe('soundness', () => {
  it('d. flipping one byte of anchor, nf, cm, epk or ct -> E_PROOF; the untouched original is accepted', async () => {
    const r = await w.replay();
    const S = w.S;
    const h = S; // S ^ 1 is S - 1 or S + 1: both carry the genesis root
    expect(r.rootAt(h ^ 1)).toBe(r.rootAt(h));
    const base = await aliceSends('bob', 1n, { noPublish: true, anchorOverride: h });

    const regions: Region[] = ['anchor', 'nf', 'cm', 'epk', 'ct'];
    const carriers = [];
    for (const region of regions) {
      const mutated = flipByte(base.envelope, region);
      const parsed = parse(mutated);
      expect(parsed.ok, region).toBe(true); // still canonical: the proof must catch it
      if (region === 'anchor' && parsed.ok) {
        expect(parsed.env.hAnchor).toBe(h ^ 1);
        expect(r.rootAt(parsed.env.hAnchor)).toBe(r.rootAt(h)); // same root: only h_body differs
      }
      carriers.push({ region, tx: await rewrap(w.node.rpc, 'alice-fee', mutated) });
    }
    await w.generateBlock([...carriers.map((c) => c.tx.hex), base.carrierHex]);
    await w.replay();
    for (const c of carriers) expect(`${c.region}:${outcome(r, c.tx.txid)}`).toBe(`${c.region}:E_PROOF`);
    expect(outcome(r, base.txid)).toBe('acc');
    await expectSupply();
  });

  it('a. out > in: the wallet refuses, the prover throws, and a cm swapped for a bigger value -> E_PROOF', async () => {
    await expect(aliceSends('bob', SUPPLY * 2n)).rejects.toThrow(/insufficient funds/);

    // Prover: a 100-unit note cannot produce 150 + 0.
    const r = await w.replay();
    const note = (await w.view('alice')).notes.find((n) => n.state === 'spendable' && n.v === 100n)!;
    const input = buildCircuitInput({
      root: r.rootAt(r.tip)!,
      hBody: 1n,
      skSpend: w.wallets.alice.keys.skSpend,
      inputs: [{ v: note.v, rseed: note.rseed, pos: note.pos!, path: r.witness(note.pos!, r.tip) }, dummyInput()],
      outputs: [
        { v: 150n, owner: w.wallets.bob.owner, rseed: randomField() },
        { v: 0n, owner: w.wallets.alice.owner, rseed: randomField() },
      ],
    });
    await expect(prove(input)).rejects.toThrow(/Assert Failed/);

    // Envelope: replace the payment output by a commitment to 1000 units for Bob
    // (with a matching ciphertext, so Bob would see 1000 if it were accepted).
    const base = await aliceSends('bob', 5n, { noPublish: true });
    const k = base.paymentIndex as 0 | 1;
    const rseed = randomField();
    const bigCm = noteCm(1000n, w.wallets.bob.owner, rseed);
    const forged = mutateEnv(base.envelope, (e) => {
      const enc = encryptNote({ v: 1000n, rseed }, w.wallets.bob.keys.pkEnc, bigCm);
      e.cm[k] = bigCm;
      e.epk[k] = enc.epk;
      e.ct[k] = enc.ct;
    });
    const bobBefore = (await w.balance('bob')).total;
    const tx = await rewrap(w.node.rpc, 'mallory-fee', forged);
    await w.generateBlock([tx.hex]);
    await w.replay();
    expect(outcome(r, tx.txid)).toBe('E_PROOF');
    expect((await w.balance('bob')).total).toBe(bobBefore);
    await expectSupply();
  });

  it('b. a norange-circuit proof of an inflating transfer, on-chain -> E_PROOF under the main vk', async () => {
    const r = await w.replay();
    const note = (await w.view('alice')).notes.find((n) => n.state === 'spendable' && n.v === 100n)!;
    // 100 in -> 200 to Bob + (r - 100) to Alice: balances mod r, needs RANGE = 0.
    const t = await craftTransfer({
      circuit: 'norange',
      root: r.rootAt(r.tip)!,
      hAnchor: r.tip,
      skSpend: w.wallets.alice.keys.skSpend,
      inputs: [{ v: note.v, rseed: note.rseed, pos: note.pos!, path: r.witness(note.pos!, r.tip) }, dummyInput()],
      outputs: [
        { v: 200n, owner: w.wallets.bob.owner, pkEnc: w.wallets.bob.keys.pkEnc },
        { v: R - 100n, owner: w.wallets.alice.owner, pkEnc: w.wallets.alice.keys.pkEnc },
      ],
    });
    expect(await verify(t.publicSignals, t.proof, 'norange')).toBe(true); // valid... for the unsafe circuit
    expect(await verify(t.publicSignals, t.proof, 'main')).toBe(false);
    const bobBefore = (await w.balance('bob')).total;
    const tx = await rewrap(w.node.rpc, 'mallory-fee', t.bytes);
    await w.generateBlock([tx.hex]);
    await w.replay();
    expect(outcome(r, tx.txid)).toBe('E_PROOF');
    expect(r.isSpent(note.nf!)).toBe(false);
    expect((await w.balance('bob')).total).toBe(bobBefore);
    await expectSupply();
  });

  it('c. a random proof of valid curve points -> E_PROOF, an off-curve one -> E_PARSE; replay keeps going', async () => {
    const base = await aliceSends('carol', 3n, { noPublish: true });
    const randomPi = withProofBytes(base.envelope, randomValidProofBytes());
    expect(parse(randomPi).ok).toBe(true);
    const offCurve = withProofBytes(base.envelope, offCurveProofBytes());
    expect(parse(offCurve).ok).toBe(false);
    const t1 = await rewrap(w.node.rpc, 'mallory-fee', randomPi);
    const t2 = await rewrap(w.node.rpc, 'mallory-fee', offCurve);
    await w.generateBlock([t1.hex, t2.hex, base.carrierHex]);
    const r = await w.replay();
    expect(outcome(r, t1.txid)).toBe('E_PROOF');
    expect(outcome(r, t2.txid)).toBe('E_PARSE');
    expect(outcome(r, base.txid)).toBe('acc');
    await expectSupply();
  });

  it("e. front-running: nfs + proof copied with the attacker's outputs -> E_PROOF; Alice's original accepted", async () => {
    const orig = await aliceSends('bob', 4n); // broadcast
    const seen = await mempoolEnvelope(orig.txid);
    const mallory = w.wallets.mallory.keys;
    const stolen = mutateEnv(seen, (e) => {
      for (const k of [0, 1] as const) {
        const rseed = randomField();
        const c = noteCm(50n, mallory.owner, rseed);
        const enc = encryptNote({ v: 50n, rseed }, mallory.pkEnc, c);
        e.cm[k] = c;
        e.epk[k] = enc.epk;
        e.ct[k] = enc.ct;
      }
    });
    const tx = await rewrap(w.node.rpc, 'mallory-fee', stolen);
    await w.generateBlock([tx.hex, orig.txid]); // the front-runner is mined first
    const r = await w.replay();
    expect(outcome(r, tx.txid)).toBe('E_PROOF');
    expect(outcome(r, orig.txid)).toBe('acc');
    expect((await w.view('mallory')).notes).toEqual([]);
    await expectSupply();
  });

  it('f. a re-randomized copy mined first is accepted and harmless; the original gets E_NF_SPENT', async () => {
    const orig = await aliceSends('bob', 6n); // broadcast
    const seen = await mempoolEnvelope(orig.txid);
    const parsed = parse(seen);
    if (!parsed.ok) throw new Error(parsed.reason);
    const newProof = proofToBytes(rerandomize(bytesToProof(parsed.env.proofBytes), vk));
    expect(Buffer.from(newProof).equals(Buffer.from(parsed.env.proofBytes))).toBe(false);
    const copy = withProofBytes(seen, newProof);
    expect(Buffer.from(copy.subarray(0, 316)).equals(Buffer.from(seen.subarray(0, 316)))).toBe(true);

    const bobBefore = (await w.balance('bob')).total;
    const tx = await rewrap(w.node.rpc, 'mallory-fee', copy);
    await w.generateBlock([tx.hex, orig.txid]);
    const r = await w.replay();
    expect(outcome(r, tx.txid)).toBe('acc');
    expect(outcome(r, orig.txid)).toBe('E_NF_SPENT');
    // Same body -> same cm/ct: Bob receives exactly the note Alice built.
    expect((await w.balance('bob')).total).toBe(bobBefore + 6n);
    const bobNote = (await w.view('bob')).notes.find((n) => n.txid === tx.txid);
    expect(bobNote?.cm).toBe(orig.env.cm[orig.paymentIndex]);
    expect(orig.spent.every((n) => r.isSpent(n.nf!))).toBe(true);
    expect((await w.view('mallory')).notes).toEqual([]);
    await expectSupply();
  });

  it('i. nf + r alias in the envelope -> E_PARSE', async () => {
    const base = await aliceSends('bob', 2n, { noPublish: true });
    const aliased = aliasNf(base.envelope, 0);
    const p = parse(aliased);
    expect(p.ok).toBe(false);
    const tx = await rewrap(w.node.rpc, 'mallory-fee', aliased);
    await w.generateBlock([tx.hex]);
    const r = await w.replay();
    expect(outcome(r, tx.txid)).toBe('E_PARSE');
    await expectSupply();
  });

  it('g. garbage ciphertext is ACCEPTED and the payment is lost (documented deviation)', async () => {
    const bobBefore = (await w.balance('bob')).total;
    const t = await aliceSends('bob', 10n, { corruptCiphertext: true }); // broadcast
    await w.mine(1);
    const r = await w.replay();
    expect(outcome(r, t.txid)).toBe('acc');
    expect((await w.balance('bob')).total).toBe(bobBefore); // Bob cannot see it
    lost += 10n;
    expect((await w.detectedSupply()).total).toBe(SUPPLY - 10n);
    await expectSupply();
  });

  it('h. anchors H-1 and H-100 accepted; H, H-101 and below S-1 -> E_ANCHOR; the rebuild is accepted', async () => {
    expect(await w.node.rpc.getRawMempool()).toEqual([]);
    await w.mine(105);
    const r = await w.replay();
    const T = r.tip;
    const H = T + 1;
    expect(H - 101).toBeGreaterThan(w.S - 1);

    // [name, anchor, fee wallet]. A released lock unlocks its fee coin, which
    // the next build from the same fee wallet could then pick while the old
    // carrier is still meant to be mined: give the early-released cases
    // (out of window) their own fee wallets.
    const cases: [string, number | undefined, string][] = [
      ['H-1', undefined, 'alice-fee'], // default anchor = tip = H - 1
      ['H-100', H - 100, 'alice-fee'],
      ['H', H, 'alice-fee'], // above the tip: lock kept until H exists
      ['H-101', H - 101, 'carol-fee'],
      ['below S-1', w.S - 2, 'mallory-fee'],
    ];
    // Each case spends a different note. Out-of-window locks are released as
    // soon as the wallet looks again, so pick the notes explicitly.
    const used = new Set<bigint>();
    const fresh = (usable: { nf?: bigint }[]) => [usable.find((n) => !used.has(n.nf!))!] as never;
    const built: { name: string; t: TransferResult }[] = [];
    for (const [name, anchor, fee] of cases) {
      const t = await aliceSends('bob', 1n, { noPublish: true, anchorOverride: anchor, selectNotes: fresh }, fee);
      used.add(t.spent[0].nf!);
      built.push({ name, t });
    }
    expect(used.size).toBe(cases.length);

    await w.generateBlock(built.map((b) => b.t.carrierHex));
    await w.replay();
    expect(built.map((b) => `${b.name}:${outcome(r, b.t.txid)}`)).toEqual([
      'H-1:acc',
      'H-100:acc',
      'H:E_ANCHOR',
      'H-101:E_ANCHOR',
      'below S-1:E_ANCHOR',
    ]);

    // The wallet notices the dead anchors, releases those locks, and rebuilds.
    // (H-101 and below S-1 were released while building the next transfer.)
    await w.view('alice');
    const reasons = Object.fromEntries(w.wallets.alice.releaseLog.map((x) => [x.txid, x.reason]));
    for (const b of built.slice(2)) expect(reasons[b.t.txid]).toBe('needs-rebuild');
    for (const b of built.slice(0, 2)) expect(reasons[b.t.txid]).toBe('spent');
    const rebuild = await aliceSends('bob', 1n);
    await w.generateBlock([rebuild.txid]);
    await w.replay();
    expect(outcome(r, rebuild.txid)).toBe('acc');
    await expectSupply();
  });
});
