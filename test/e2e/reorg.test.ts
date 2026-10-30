// Reorgs: the shielded state is a pure function of the active chain, so a
// reorg can undo a spend, flip a double-spend winner, or invalidate an anchor.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { extractEnvelope } from '../../src/codec.js';
import { bytesToHex } from '../../src/crypto.js';
import { Replay } from '../../src/indexer.js';
import { shutdownProver } from '../../src/prover.js';
import type { TransferResult } from '../../src/wallet.js';
import { makeWorld, type World } from '../helpers/world.js';

let w: World;

function outcome(r: Replay, txid: string): string {
  if (r.accepted.some((a) => a.txid === txid)) return 'acc';
  return r.rejected.find((x) => x.txid === txid)?.code ?? 'absent';
}

async function expectFreshAgrees(): Promise<string> {
  const d = (await w.replay()).digest().hex;
  expect((await Replay.fresh(w.node.rpc, w.opts)).digest().hex).toBe(d);
  return d;
}

const send = async (to: string, amount: bigint, feeWallet: string, hooks = {}): Promise<TransferResult> =>
  w.wallets.alice.buildTransfer({
    replay: await w.replay(),
    rpc: w.node.rpc,
    to: w.wallets[to].address(),
    amount,
    feeWallet,
    hooks,
  });

beforeAll(async () => {
  w = await makeWorld({
    actors: ['alice', 'bob', 'carol'],
    genesis: { alice: [100n, 100n, 100n] },
    extraFeeWallets: ['alice2-fee'],
  });
});

afterAll(async () => {
  await w?.stop();
  await shutdownProver();
});

describe('reorg', () => {
  it('a. a reorg removing a spend: back to candidate / pending, then re-accepted with the same proof bytes', async () => {
    const A = await send('bob', 30n, 'alice-fee'); // broadcast
    const [hH] = await w.mine(1);
    let r = await w.replay();
    expect(outcome(r, A.txid)).toBe('acc');

    await w.node.rpc.invalidateBlock(hH);
    await w.generateBlock([]);
    await w.generateBlock([]); // empty blocks: the carrier stays in the mempool
    r = await w.replay();
    expect(await w.node.rpc.getRawMempool()).toContain(A.txid);
    expect(A.nfs.some((n) => r.isSpent(n))).toBe(false);
    expect(outcome(r, A.txid)).toBe('absent');

    // The anchor (old tip) is still on the active chain with the same root.
    expect(r.rootAt(A.anchorHeight)?.toString()).toBe(w.wallets.alice.locks[0]?.anchorRoot);
    expect((await w.view('bob')).notes.map((n) => [n.state, n.v])).toEqual([['candidate', 30n]]);
    const alice = await w.view('alice');
    expect(alice.released).toEqual([]);
    expect(alice.notes.find((n) => n.nf === A.spent[0].nf)?.state).toBe('pending-spend');
    expect((await w.supplyInvariant()).total).toBe(300n);
    await expectFreshAgrees();

    // Mine the same carrier again: accepted, with the very same envelope bytes.
    const h2 = await w.generateBlock([A.txid]);
    r = await w.replay();
    expect(outcome(r, A.txid)).toBe('acc');
    const block = await w.node.rpc.getBlock(h2, 2);
    const ex = extractEnvelope(block.tx.find((t) => t.txid === A.txid)!);
    expect(ex.kind === 'envelope' && bytesToHex(ex.bytes)).toBe(bytesToHex(A.envelope));
    expect((await w.view('bob')).notes.map((n) => [n.state, n.v])).toEqual([['spendable', 30n]]);
    expect((await w.supplyInvariant()).total).toBe(300n);
    await expectFreshAgrees();
  });

  it('b. a reorg flipping the winner: Carol gets the note, re-mining A -> E_NF_SPENT; reconsidering the old branch changes nothing', async () => {
    const P = await send('bob', 20n, 'alice-fee', { noPublish: true });
    const Q = await send('carol', 20n, 'alice2-fee', { noPublish: true, ignoreLocks: true });
    expect(Q.spent[0].nf).toBe(P.spent[0].nf);
    const bobBefore = (await w.balance('bob')).total;

    const hOld = await w.generateBlock([P.carrierHex]);
    let r = await w.replay();
    expect(outcome(r, P.txid)).toBe('acc');
    expect((await w.balance('bob')).total).toBe(bobBefore + 20n);

    await w.node.rpc.invalidateBlock(hOld); // P goes back to the mempool
    await w.generateBlock([Q.carrierHex]);
    await w.generateBlock([]); // the new branch now has more work
    r = await w.replay();
    expect(outcome(r, Q.txid)).toBe('acc');
    expect(outcome(r, P.txid)).toBe('absent');
    expect((await w.balance('carol')).total).toBe(20n);
    expect((await w.balance('bob')).total).toBe(bobBefore);
    // P is in the mempool but would be E_NF_SPENT: not even a candidate for Bob.
    expect(await w.node.rpc.getRawMempool()).toContain(P.txid);
    expect((await w.view('bob')).notes.some((n) => n.state === 'candidate')).toBe(false);

    await w.generateBlock([P.txid]);
    r = await w.replay();
    expect(outcome(r, P.txid)).toBe('E_NF_SPENT');
    const best = await w.node.rpc.getBestBlockHash();
    const d = await expectFreshAgrees();

    await w.node.rpc.reconsiderBlock(hOld); // 1 block vs 3: the old branch has less work
    expect(await w.node.rpc.getBestBlockHash()).toBe(best);
    expect((await w.replay()).digest().hex).toBe(d);
    expect((await w.supplyInvariant()).total).toBe(300n);
  });

  it('c. a stale anchor: the anchor block is replaced -> E_PROOF; the wallet rebuilds and the rebuild is accepted', async () => {
    const T1 = await send('carol', 5n, 'alice-fee'); // broadcast; changes the root at H
    const [hH] = await w.mine(1);
    let r = await w.replay();
    expect(outcome(r, T1.txid)).toBe('acc');
    const H = r.tip;
    const rootH = r.rootAt(H)!;

    // T2 anchors at H, whose root includes T1. Kept unbroadcast so its fee coin
    // stays locked. It spends a note created BEFORE H: had it spent T1's change
    // (created in H), that note would itself vanish with the reorg and only
    // reappear as a mempool candidate.
    const T2 = await send('bob', 7n, 'alice-fee', {
      noPublish: true,
      selectNotes: (u: { height?: number }[]) => [u.find((n) => n.height! < H)!] as never,
    });
    expect(T2.anchorHeight).toBe(H);
    const fee = w.node.rpc.wallet('alice-fee');
    const isLocked = async () =>
      (await fee.listLockUnspent()).some((o) => T2.fundingOutpoints.some((f) => f.txid === o.txid && f.vout === o.vout));
    expect(await isLocked()).toBe(true);

    // Replace block H by an empty block: height H exists again with another root.
    await w.node.rpc.invalidateBlock(hH);
    await w.generateBlock([]);
    r = await w.replay();
    expect(r.tip).toBe(H);
    expect(r.rootAt(H)).not.toBe(rootH);

    // The wallet sees the anchor root changed: needs rebuild, lock released, coins unlocked.
    const v = await w.view('alice');
    expect(v.released).toContainEqual({ txid: T2.txid, reason: 'needs-rebuild' });
    expect(w.wallets.alice.locks.some((l) => l.txid === T2.txid)).toBe(false);
    expect(await isLocked()).toBe(false);
    expect(v.notes.find((n) => n.nf === T2.spent[0].nf)?.state).toBe('spendable');

    // If the stale carrier is mined anyway: height H exists, so the anchor is in
    // the window, but R[H] is not the root the proof used -> E_PROOF.
    // T2's carrier spends the fee change of T1's carrier (back in the mempool),
    // so T1 must precede it in the block: fee coins chain the carriers. T1's own
    // anchor (H-1) is untouched, so T1 is accepted again.
    await w.generateBlock([T1.txid, T2.carrierHex]);
    r = await w.replay();
    expect(outcome(r, T1.txid)).toBe('acc');
    expect(outcome(r, T2.txid)).toBe('E_PROOF');

    const rebuilt = await send('bob', 7n, 'alice-fee');
    await w.generateBlock([rebuilt.txid]);
    r = await w.replay();
    expect(outcome(r, rebuilt.txid)).toBe('acc');
    expect((await w.supplyInvariant()).total).toBe(300n);
    await expectFreshAgrees();
  });
});
