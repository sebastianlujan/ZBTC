// Double spends at the shielded layer. The two carriers spend coins of
// different fee wallets, so Bitcoin sees no conflict: only the nullifier rule
// decides, by block order (first nullifier wins).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Replay } from '../../src/indexer.js';
import { shutdownProver } from '../../src/prover.js';
import type { TransferResult } from '../../src/wallet.js';
import { rewrap, setNfsEqual } from '../helpers/craft.js';
import { makeWorld, type World } from '../helpers/world.js';

function outcome(r: Replay, txid: string): string {
  if (r.accepted.some((a) => a.txid === txid)) return 'acc';
  return r.rejected.find((x) => x.txid === txid)?.code ?? 'absent';
}

afterAll(async () => {
  await shutdownProver();
});

describe('double spend: ordering by generateblock', () => {
  let w: World;
  let A: TransferResult; // alice -> bob 30   (fee: alice-fee)
  let B: TransferResult; // alice -> carol 30 (fee: alice2-fee), same note

  beforeAll(async () => {
    w = await makeWorld({
      actors: ['alice', 'bob', 'carol'],
      genesis: { alice: 100n },
      extraFeeWallets: ['alice2-fee'],
    });
    const alice = w.wallets.alice;
    const replay = await w.replay();
    A = await alice.buildTransfer({
      replay,
      rpc: w.node.rpc,
      to: w.wallets.bob.address(),
      amount: 30n,
      feeWallet: 'alice-fee',
      hooks: { noPublish: true },
    });
    B = await alice.buildTransfer({
      replay,
      rpc: w.node.rpc,
      to: w.wallets.carol.address(),
      amount: 30n,
      feeWallet: 'alice2-fee',
      hooks: { noPublish: true, ignoreLocks: true },
    });
    // Same input note -> same real nullifier; the dummy nullifiers differ.
    expect(A.spent[0].nf).toBe(B.spent[0].nf);
    expect(A.nfs).toContain(A.spent[0].nf);
    expect(B.nfs).toContain(A.spent[0].nf);
  });

  afterAll(async () => {
    await w?.stop();
  });

  let hAB: string;
  let hBA: string;

  it('a. [A, B] in one block: A accepted, B E_NF_SPENT; Bob 30, Carol nothing', async () => {
    hAB = await w.generateBlock([A.carrierHex, B.carrierHex]);
    const r = await w.replay();
    expect(outcome(r, A.txid)).toBe('acc');
    expect(outcome(r, B.txid)).toBe('E_NF_SPENT');
    expect((await w.balance('bob')).total).toBe(30n);
    expect((await w.view('carol')).notes).toEqual([]);
    expect((await w.supplyInvariant()).total).toBe(100n);
  });

  it('b. [B, A] (after invalidating a.): B accepted, A E_NF_SPENT; Carol 30, Bob nothing', async () => {
    await w.node.rpc.invalidateBlock(hAB);
    hBA = await w.generateBlock([B.carrierHex, A.carrierHex]);
    const r = await w.replay();
    expect(outcome(r, B.txid)).toBe('acc');
    expect(outcome(r, A.txid)).toBe('E_NF_SPENT');
    expect((await w.balance('carol')).total).toBe(30n);
    expect((await w.view('bob')).notes).toEqual([]);
    expect((await w.supplyInvariant()).total).toBe(100n);
  });

  it('c. A in H, B in H+1: B E_NF_SPENT in the later block', async () => {
    await w.node.rpc.invalidateBlock(hBA);
    await w.generateBlock([A.carrierHex]);
    await w.generateBlock([B.carrierHex]);
    const r = await w.replay();
    expect(outcome(r, A.txid)).toBe('acc');
    const rejB = r.rejected.find((x) => x.txid === B.txid);
    expect(rejB?.code).toBe('E_NF_SPENT');
    expect(rejB?.height).toBe(r.accepted.find((a) => a.txid === A.txid)!.height + 1);
    expect((await w.balance('bob')).total).toBe(30n);
    expect((await w.balance('carol')).total).toBe(0n);
    expect((await w.supplyInvariant()).total).toBe(100n);
  });

  it('e. crafted nf0 == nf1 -> E_NF_DUP, without any proof verification', async () => {
    const dup = setNfsEqual(A.envelope);
    const carrier = await rewrap(w.node.rpc, 'alice2-fee', dup);
    const r = await w.replay();
    const before = r.verifyCalls;
    await w.generateBlock([carrier.hex]);
    await w.replay();
    expect(outcome(r, carrier.txid)).toBe('E_NF_DUP');
    expect(r.verifyCalls).toBe(before);
    expect((await w.supplyInvariant()).total).toBe(100n);
  });
});

describe('double spend: mempool race', () => {
  let w: World;

  beforeAll(async () => {
    w = await makeWorld({
      actors: ['alice', 'bob', 'carol'],
      genesis: { alice: 100n },
      extraFeeWallets: ['alice2-fee'],
    });
  });

  afterAll(async () => {
    await w?.stop();
  });

  it('d. both carriers broadcast, one block mined: exactly one accepted, the first in block order', async () => {
    const C = await w.send('alice', 'bob', 30n); // fee: alice-fee
    const D = await w.wallets.alice.buildTransfer({
      replay: await w.replay(),
      rpc: w.node.rpc,
      to: w.wallets.carol.address(),
      amount: 30n,
      feeWallet: 'alice2-fee',
      hooks: { ignoreLocks: true },
    });
    expect(D.spent[0].nf).toBe(C.spent[0].nf);
    expect(await w.node.rpc.getRawMempool()).toEqual(expect.arrayContaining([C.txid, D.txid]));

    // Before mining, both recipients see a candidate (never counted).
    expect((await w.view('bob')).notes.map((n) => [n.state, n.v])).toEqual([['candidate', 30n]]);
    expect((await w.view('carol')).notes.map((n) => [n.state, n.v])).toEqual([['candidate', 30n]]);
    expect((await w.supplyInvariant()).total).toBe(100n);

    const [hash] = await w.mine(1);
    const block = await w.node.rpc.getBlock(hash, 2);
    const order = block.tx.map((t) => t.txid).filter((id) => id === C.txid || id === D.txid);
    expect(order).toHaveLength(2);
    const [winner, loser] = order;

    const r = await w.replay();
    expect(outcome(r, winner)).toBe('acc');
    expect(outcome(r, loser)).toBe('E_NF_SPENT');

    const [winTo, loseTo] = winner === C.txid ? ['bob', 'carol'] : ['carol', 'bob'];
    console.log(`[double-spend d] block order put ${winner === C.txid ? 'C (->bob)' : 'D (->carol)'} first`);
    expect((await w.view(winTo)).notes.map((n) => [n.state, n.v])).toEqual([['spendable', 30n]]);
    expect((await w.view(loseTo)).notes).toEqual([]);
    expect((await w.supplyInvariant()).total).toBe(100n);
  });
});
