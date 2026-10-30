// Indexer replay logic on synthetic blocks (no bitcoind). Envelopes are real
// (craftTransfer proves them), blocks and txids are fake but well-formed.
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { envelopeScript, OFF_CT, OFF_NF, OFF_VERSION } from '../../src/codec.js';
import { R } from '../../src/constants.js';
import { bytesToHex, keysFromSeed, randomField } from '../../src/crypto.js';
import {
  ChainMismatchError,
  loadGenesis,
  makeGenesis,
  Replay,
  type BlockLike,
  type GenesisNote,
} from '../../src/indexer.js';
import { dummyInput, shutdownProver } from '../../src/prover.js';
import { NoteTree } from '../../src/tree.js';
import { craftTransfer } from '../helpers/craft.js';
import { replayOptionsFor } from '../helpers/fixtures.js';

const alice = keysFromSeed(new Uint8Array(32).fill(0xa1));
const bob = keysFromSeed(new Uint8Array(32).fill(0xb0));

// ---- Genesis: S = 10, notes G1..G4 (Alice) + G5 (Bob) at positions 0..4 ----
const S = 10;
const G: GenesisNote[] = [
  { v: 100n, owner: alice.owner, rseed: randomField() },
  { v: 50n, owner: alice.owner, rseed: randomField() },
  { v: 40n, owner: alice.owner, rseed: randomField() },
  { v: 30n, owner: alice.owner, rseed: randomField() },
  { v: 20n, owner: bob.owner, rseed: randomField() },
];
const genesisText = makeGenesis(G, S);
const opts = replayOptionsFor(genesisText);
const genesisTree = new NoteTree(opts.genesis.notes.map((n) => n.cm));
const R0 = genesisTree.root();

// ---- Synthetic chain ----
const h32 = (s: string) => bytesToHex(sha256(utf8ToBytes(s)));
const P2WPKH = '0014' + '22'.repeat(20);

class FakeChain {
  height: number;
  private prev: string;
  constructor(
    private readonly salt = 'main',
    base = S - 1,
  ) {
    this.height = base;
    this.prev = h32(`${salt}:${base}`);
  }
  /** One block; tx 0 is a coinbase-like tx without OP_RETURN, then one tx per script list. */
  block(...txs: string[][]): BlockLike & { height: number } {
    const height = ++this.height;
    const hash = h32(`${this.salt}:block:${height}`);
    const all = [[P2WPKH], ...txs];
    const b = {
      hash,
      height,
      previousblockhash: this.prev,
      tx: all.map((scripts, i) => ({
        txid: h32(`${this.salt}:tx:${height}:${i}:${scripts.join()}`),
        vout: scripts.map((hex, n) => ({ n, scriptPubKey: { hex } })),
      })),
    };
    this.prev = hash;
    return b;
  }
}

const envTx = (bytes: Uint8Array) => [P2WPKH, bytesToHex(envelopeScript(bytes))];

async function applyAll(r: Replay, blocks: (BlockLike & { height: number })[]): Promise<void> {
  for (const b of blocks) await r.applyBlock(b.height, b);
}

function patched(bytes: Uint8Array, at: number, data: Uint8Array): Uint8Array {
  const b = bytes.slice();
  b.set(data, at);
  return b;
}

// ---- Envelopes (proved once) ----
const E: Record<string, Uint8Array> = {};

async function spend(noteIdx: number, hAnchor: number, toBob: bigint): Promise<Uint8Array> {
  const n = G[noteIdx];
  const t = await craftTransfer({
    root: R0,
    hAnchor,
    skSpend: alice.skSpend,
    inputs: [{ v: n.v, rseed: n.rseed, pos: noteIdx, path: genesisTree.witness(noteIdx) }, dummyInput()],
    outputs: [
      { v: toBob, owner: bob.owner, pkEnc: bob.pkEnc },
      { v: n.v - toBob, owner: alice.owner, pkEnc: alice.pkEnc },
    ],
  });
  return t.bytes;
}

beforeAll(async () => {
  E.A = await spend(0, S - 1, 30n); // G1, anchor S-1
  E.B = await spend(0, S - 1, 99n); // G1 again: conflicts with A
  E.C = await spend(1, S - 1, 5n); // G2, anchor S-1
  E.at10 = await spend(2, 10, 1n); // anchored at H itself when mined at H = 10
  E.below = await spend(3, S - 2, 1n); // below S-1
  E.hm1 = await spend(1, 115, 2n); // H-1 at H = 116
  E.hm100 = await spend(2, 16, 3n); // H-100 at H = 116
  E.h = await spend(3, 116, 4n); // H at H = 116
  E.hm101 = await spend(3, 15, 5n); // H-101 at H = 116
});

afterAll(async () => {
  await shutdownProver();
});

const codes = (r: Replay) => r.rejected.map((x) => x.code);

describe('genesis', () => {
  it('loads, sets R[S-1] and treeSize[S-1], and is chain-independent', () => {
    const r = new Replay(opts);
    expect(r.tip).toBe(S - 1);
    expect(r.tipHash).toBeNull();
    expect(r.rootAt(S - 1)).toBe(R0);
    expect(r.treeSizeAt(S - 1)).toBe(G.length);
    expect(opts.genesis.totalSupply).toBe(240n);
    expect(() => r.rollback()).toThrow(/below/);
  });

  it('rejects sum mismatch, out-of-range values and malformed fields', () => {
    const doc = JSON.parse(genesisText);
    const bad = (mut: (d: any) => void) => {
      const d = structuredClone(doc);
      mut(d);
      return () => loadGenesis(JSON.stringify(d));
    };
    expect(bad((d) => (d.totalSupply = '241'))).toThrow(/totalSupply/);
    expect(bad((d) => (d.notes[0].v = (1n << 64n).toString()))).toThrow(/2\^64/);
    expect(bad((d) => (d.notes[0].owner = R.toString()))).toThrow(/owner/);
    expect(bad((d) => (d.notes[0].rseed = R.toString()))).toThrow(/rseed/);
    expect(bad((d) => (d.notes[0].v = '010'))).toThrow(/decimal/);
    expect(bad((d) => (d.notes[0].v = 100))).toThrow(/decimal/);
    expect(bad((d) => (d.startHeight = 0))).toThrow(/startHeight/);
    expect(bad((d) => (d.version = 2))).toThrow(/version/);
  });
});

describe('applyBlock', () => {
  it('accepts a valid transfer and records outputs, nullifiers and R[H]', async () => {
    const r = new Replay(opts);
    const chain = new FakeChain();
    await applyAll(r, [chain.block(envTx(E.A))]);
    expect(r.acceptedCount).toBe(1);
    expect(r.rejected).toHaveLength(0);
    const acc = r.accepted[0];
    expect(acc).toMatchObject({ height: 10, txIndex: 1, hAnchor: S - 1 });
    expect(acc.outputs.map((o) => o.pos)).toEqual([5, 6]);
    expect(acc.nfs.every((n) => r.isSpent(n))).toBe(true);
    expect(r.rootAt(10)).not.toBe(R0);
    expect(r.rootAt(S - 1)).toBe(R0);
    expect(r.treeSizeAt(10)).toBe(7);
    expect(r.outputs().map((o) => [o.pos, o.index, o.height])).toEqual([
      [5, 0, 10],
      [6, 1, 10],
    ]);
    expect(r.verifyCalls).toBe(1);
  });

  it('the same envelope in a later block -> E_NF_SPENT without a proof check; empty-effect block carries R forward', async () => {
    const r = new Replay(opts);
    const chain = new FakeChain();
    await applyAll(r, [chain.block(envTx(E.A)), chain.block(envTx(E.A))]);
    expect(codes(r)).toEqual(['E_NF_SPENT']);
    expect(r.verifyCalls).toBe(1);
    expect(r.rootAt(11)).toBe(r.rootAt(10));
    expect(r.treeSizeAt(11)).toBe(r.treeSizeAt(10));
    await applyAll(r, [chain.block()]); // truly empty block
    expect(r.rootAt(12)).toBe(r.rootAt(10));
  });

  it('two conflicting envelopes in one block: the first in block order wins', async () => {
    const r1 = new Replay(opts);
    await applyAll(r1, [new FakeChain().block(envTx(E.A), envTx(E.B))]);
    expect(r1.accepted.map((a) => a.txIndex)).toEqual([1]);
    expect(r1.rejected.map((x) => [x.txIndex, x.code])).toEqual([[2, 'E_NF_SPENT']]);

    const r2 = new Replay(opts);
    await applyAll(r2, [new FakeChain().block(envTx(E.B), envTx(E.A))]);
    expect(r2.accepted.map((a) => a.txIndex)).toEqual([1]);
    expect(r2.accepted[0].hBody).not.toBe(r1.accepted[0].hBody); // B won this time
    expect(r2.rejected.map((x) => [x.txIndex, x.code])).toEqual([[2, 'E_NF_SPENT']]);
  });

  it('nf0 == nf1 -> E_NF_DUP without calling verify', async () => {
    const r = new Replay(opts);
    const dup = patched(E.A, OFF_NF + 32, E.A.subarray(OFF_NF, OFF_NF + 32));
    await applyAll(r, [new FakeChain().block(envTx(dup))]);
    expect(codes(r)).toEqual(['E_NF_DUP']);
    expect(r.verifyCalls).toBe(0);
  });

  it('anchor window: below S-1 and H itself -> E_ANCHOR; R[H] is not visible mid-block', async () => {
    const r = new Replay(opts);
    const chain = new FakeChain();
    // H = 10: A changes the tree, C (anchor 9) still verifies against the pre-block R[9],
    // at10 (anchor = H) is rejected, below (anchor S-2) is rejected.
    await applyAll(r, [chain.block(envTx(E.A), envTx(E.C), envTx(E.at10), envTx(E.below))]);
    expect(r.accepted.map((a) => a.txIndex)).toEqual([1, 2]);
    expect(r.rejected.map((x) => [x.txIndex, x.code])).toEqual([
      [3, 'E_ANCHOR'],
      [4, 'E_ANCHOR'],
    ]);
    expect(r.verifyCalls).toBe(2);
    expect(r.rootAt(S - 1)).toBe(R0);
  });

  it('anchor window at H = 116: H-1 and H-100 accepted, H and H-101 -> E_ANCHOR', async () => {
    const r = new Replay(opts);
    const chain = new FakeChain();
    const empties = Array.from({ length: 106 }, () => chain.block()); // heights 10..115
    const t0 = performance.now();
    await applyAll(r, empties);
    const emptyMs = (performance.now() - t0) / empties.length;
    expect(r.tip).toBe(115);
    expect(r.rootAt(115)).toBe(R0);

    const t1 = performance.now();
    await applyAll(r, [chain.block(envTx(E.h), envTx(E.hm101), envTx(E.hm100), envTx(E.hm1))]);
    const busyMs = performance.now() - t1;
    console.log(
      `[replay] empty block ${(emptyMs * 1000).toFixed(1)} us; block with 4 envelopes (2 proofs) ${busyMs.toFixed(1)} ms`,
    );

    expect(r.rejected.map((x) => [x.txIndex, x.code])).toEqual([
      [1, 'E_ANCHOR'],
      [2, 'E_ANCHOR'],
    ]);
    expect(r.accepted.map((a) => [a.txIndex, a.hAnchor])).toEqual([
      [3, 16],
      [4, 115],
    ]);
    expect(r.verifyCalls).toBe(2);
  });

  it('E_MULTI, E_PARSE (carrier and body) and E_PROOF', async () => {
    const r = new Replay(opts);
    const script = bytesToHex(envelopeScript(E.A));
    const badVersion = patched(E.A, OFF_VERSION, new Uint8Array([2]));
    const flippedCt = E.A.slice();
    flippedCt[OFF_CT] ^= 1;
    await applyAll(r, [
      new FakeChain().block(
        [P2WPKH, script, script], // two magic OP_RETURNs
        [P2WPKH, '6a4e3c020000' + bytesToHex(E.A)], // non-minimal push
        envTx(badVersion), // canonical carrier, bad body
        envTx(flippedCt), // h_body changes -> proof fails
      ),
    ]);
    expect(codes(r)).toEqual(['E_MULTI', 'E_PARSE', 'E_PARSE', 'E_PROOF']);
    expect(r.acceptedCount).toBe(0);
    expect(r.verifyCalls).toBe(1);
  });

  it('applyBlock is not reentrant (a concurrent call cannot apply the same block twice)', async () => {
    const r = new Replay(opts);
    const b = new FakeChain().block(envTx(E.A));
    const first = r.applyBlock(b.height, b);
    await expect(r.applyBlock(b.height, b)).rejects.toThrow(/not reentrant/);
    await first;
    expect(r.acceptedCount).toBe(1);
    expect(r.tip).toBe(b.height);
  });

  it('refuses blocks that do not extend the tip and leaves state untouched', async () => {
    const r = new Replay(opts);
    const chain = new FakeChain();
    await applyAll(r, [chain.block(envTx(E.A))]);
    const before = r.digest().hex;
    const orphan = new FakeChain('other', 10).block(envTx(E.C)); // height 11, wrong parent
    await expect(r.applyBlock(11, orphan)).rejects.toBeInstanceOf(ChainMismatchError);
    await expect(r.applyBlock(13, chain.block())).rejects.toThrow(/tip is 10/);
    expect(r.digest().hex).toBe(before);
  });
});

describe('rollback and digest', () => {
  it('rollback then re-apply gives an identical digest; rollback equals a shorter fresh replay', async () => {
    const chain = new FakeChain();
    const b10 = chain.block(envTx(E.A));
    const b11 = chain.block(envTx(E.A)); // E_NF_SPENT
    const b12 = chain.block(envTx(E.C));

    const r = new Replay(opts);
    const d0 = r.digest().hex;
    await applyAll(r, [b10, b11, b12]);
    const d12 = r.digest();
    expect(r.acceptedCount).toBe(2);

    r.rollback();
    r.rollback();
    const short = new Replay(opts);
    await applyAll(short, [b10]);
    expect(r.digest()).toEqual(short.digest());
    expect(r.rejected).toHaveLength(0);
    expect(r.isSpent(r.accepted[0].nfs[0])).toBe(true);

    await applyAll(r, [b11, b12]);
    expect(r.digest()).toEqual(d12);

    r.rollback();
    r.rollback();
    r.rollback();
    expect(r.digest().hex).toBe(d0);
    expect(r.treeSize).toBe(G.length);
  });

  it('witness(pos, anchor) uses the tree size at the anchor, not the current size', async () => {
    const r = new Replay(opts);
    const chain = new FakeChain();
    await applyAll(r, [chain.block(envTx(E.A))]);
    const w10 = r.witness(5, 10);
    await applyAll(r, [chain.block(envTx(E.C))]);
    expect(r.witness(5, 10)).toEqual(w10);
    const cm5 = r.outputs()[0].cm;
    expect(NoteTree.verifyPath(cm5, 5, r.witness(5, 10))).toBe(r.rootAt(10));
    expect(NoteTree.verifyPath(cm5, 5, r.witness(5, 11))).toBe(r.rootAt(11));
    expect(() => r.witness(0, 99)).toThrow(RangeError);
  });

  it('nfHash does not depend on nullifier insertion order; same chain -> same digest', async () => {
    const x = new Replay(opts);
    await applyAll(x, [new FakeChain().block(envTx(E.A), envTx(E.C))]);
    const y = new Replay(opts);
    await applyAll(y, [new FakeChain().block(envTx(E.C), envTx(E.A))]);
    const dx = x.digest();
    const dy = y.digest();
    expect(dx.nfHash).toBe(dy.nfHash); // same set, different insertion order
    expect(dx.histHash).not.toBe(dy.histHash); // history order differs
    expect(dx.root).not.toBe(dy.root); // leaf order differs

    const x2 = new Replay(opts);
    await applyAll(x2, [new FakeChain().block(envTx(E.A), envTx(E.C))]);
    expect(x2.digest()).toEqual(dx);
    expect(dx.profile).toBe(new Replay(opts).digest().profile);
  });
});
