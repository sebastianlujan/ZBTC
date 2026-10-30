// E2E indexer on a real bitcoind: accept, replay in a new carrier ->
// E_NF_SPENT, reorg away and back, incremental sync == fresh replay.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { keysFromSeed, randomField } from '../../src/crypto.js';
import { makeGenesis, Replay, type ReplayOptions } from '../../src/indexer.js';
import { dummyInput, shutdownProver } from '../../src/prover.js';
import { publishEnvelope } from '../../src/rpc.js';
import { NoteTree } from '../../src/tree.js';
import { craftTransfer, type CraftedTransfer } from '../helpers/craft.js';
import { replayOptionsFor } from '../helpers/fixtures.js';
import { fundWallet, initMiner, mine, startNode, type RegtestNode } from '../helpers/regtest.js';

const alice = keysFromSeed(new Uint8Array(32).fill(0xa1));
const bob = keysFromSeed(new Uint8Array(32).fill(0xb0));

let node: RegtestNode;
let opts: ReplayOptions;
let S: number;
let inc: Replay;
let crafted: CraftedTransfer;
let tx1: string;
let tx2: string;
let hashS: string;
let digestBefore: string;

async function freshDigest(): Promise<string> {
  return (await Replay.fresh(node.rpc, opts)).digest().hex;
}

beforeAll(async () => {
  node = await startNode({ txindex: true });
  await initMiner(node);
  await fundWallet(node, 'fee-a', 1);
  await fundWallet(node, 'fee-b', 1);

  // Genesis: Alice holds 100 units; replay starts at the next block.
  S = (await node.rpc.getBlockCount()) + 1;
  const note = { v: 100n, owner: alice.owner, rseed: randomField() };
  opts = replayOptionsFor(makeGenesis([note], S));

  const tree = new NoteTree([opts.genesis.notes[0].cm]);
  crafted = await craftTransfer({
    root: tree.root(),
    hAnchor: S - 1,
    skSpend: alice.skSpend,
    inputs: [{ v: 100n, rseed: note.rseed, pos: 0, path: tree.witness(0) }, dummyInput()],
    outputs: [
      { v: 30n, owner: bob.owner, pkEnc: bob.pkEnc },
      { v: 70n, owner: alice.owner, pkEnc: alice.pkEnc },
    ],
  });
  inc = new Replay(opts);
});

afterAll(async () => {
  await node?.stop();
  await shutdownProver();
});

describe('indexer on regtest', () => {
  it('starts at S-1 with the genesis root', async () => {
    expect(await inc.sync(node.rpc)).toEqual({ rolledBack: 0, applied: 0 });
    expect(inc.tip).toBe(S - 1);
    expect(inc.rootAt(S - 1)).toBeDefined();
  });

  it('accepts a published transfer anchored at S-1', async () => {
    tx1 = (await publishEnvelope(node.rpc, 'fee-a', crafted.bytes)).txid;
    await mine(node, 1);
    expect(await inc.sync(node.rpc)).toEqual({ rolledBack: 0, applied: 1 });
    expect(inc.acceptedCount).toBe(1);
    expect(inc.accepted[0]).toMatchObject({ height: S, txid: tx1, hAnchor: S - 1 });
    expect(inc.isSpent(crafted.env.nf[0])).toBe(true);
  });

  it('the same envelope bytes in a new carrier tx (other fee wallet) -> E_NF_SPENT', async () => {
    tx2 = (await publishEnvelope(node.rpc, 'fee-b', crafted.bytes)).txid;
    expect(tx2).not.toBe(tx1);
    await mine(node, 1);
    expect(await inc.sync(node.rpc)).toEqual({ rolledBack: 0, applied: 1 });
    expect(inc.rejected.map((r) => [r.height, r.txid, r.code])).toEqual([[S + 1, tx2, 'E_NF_SPENT']]);
    expect(inc.acceptedCount).toBe(1);

    digestBefore = inc.digest().hex;
    expect(await freshDigest()).toBe(digestBefore);
  });

  it('a reorg removing the transfer: incremental sync == fresh replay, nf no longer spent', async () => {
    hashS = await node.rpc.getBlockHash(S);
    await node.rpc.invalidateBlock(hashS);
    for (let i = 0; i < 2; i++) await node.rpc.generateBlock(node.miner!.address, []);
    expect(await node.rpc.getBlockCount()).toBe(S + 1);
    // Both carriers are back in the mempool; replay must ignore them.
    expect(await node.rpc.getRawMempool()).toEqual(expect.arrayContaining([tx1, tx2]));

    expect(await inc.sync(node.rpc)).toEqual({ rolledBack: 2, applied: 2 });
    expect(inc.isSpent(crafted.env.nf[0])).toBe(false);
    expect(inc.isSpent(crafted.env.nf[1])).toBe(false);
    expect(inc.acceptedCount).toBe(0);
    expect(inc.rejected).toHaveLength(0);
    expect(inc.rootAt(S + 1)).toBe(inc.rootAt(S - 1));
    const d = inc.digest().hex;
    expect(d).not.toBe(digestBefore);
    expect(await freshDigest()).toBe(d);
  });

  it('restoring the original branch: digests agree again and equal the pre-reorg digest', async () => {
    await node.rpc.invalidateBlock(await node.rpc.getBlockHash(S));
    await node.rpc.reconsiderBlock(hashS);
    expect(await node.rpc.getBlockHash(S)).toBe(hashS);
    expect(await node.rpc.getBlockCount()).toBe(S + 1);

    expect(await inc.sync(node.rpc)).toEqual({ rolledBack: 2, applied: 2 });
    expect(inc.isSpent(crafted.env.nf[0])).toBe(true);
    expect(inc.rejected.map((r) => r.code)).toEqual(['E_NF_SPENT']);
    expect(inc.digest().hex).toBe(digestBefore);
    expect(await freshDigest()).toBe(digestBefore);
  });

  it('measures replay cost per block (RPC included)', async () => {
    await mine(node, 30);
    const t0 = performance.now();
    const fresh = await Replay.fresh(node.rpc, opts);
    const ms = performance.now() - t0;
    const blocks = fresh.tip - (S - 1);
    console.log(
      `[replay] fresh replay of ${blocks} blocks (1 verified proof): ${ms.toFixed(0)} ms, ${(ms / blocks).toFixed(1)} ms/block`,
    );
    await inc.sync(node.rpc);
    expect(fresh.digest()).toEqual(inc.digest());
  });
});
