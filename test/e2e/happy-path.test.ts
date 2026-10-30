// Alice (100) -> Bob 30 -> Carol 10, with every note state observed, the
// supply invariant checked at each step, and a CLI process agreeing on the digest.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { REPO_ROOT } from '../../src/constants.js';
import { shutdownProver } from '../../src/prover.js';
import type { NoteView } from '../../src/wallet.js';
import { makeWorld, type World } from '../helpers/world.js';

let w: World;

beforeAll(async () => {
  w = await makeWorld({ actors: ['alice', 'bob', 'carol'], genesis: { alice: 100n } });
});

afterAll(async () => {
  await w?.stop();
  await shutdownProver();
});

const pick = (notes: NoteView[]) => notes.map((n) => ({ state: n.state, v: n.v }));

describe('happy path', () => {
  it('genesis: alice holds 100 spendable, supply invariant holds', async () => {
    expect(pick((await w.view('alice')).notes)).toEqual([{ state: 'spendable', v: 100n }]);
    expect((await w.balance('alice')).total).toBe(100n);
    expect((await w.supplyInvariant()).total).toBe(100n);
  });

  it('alice -> bob 30: candidate for bob, pending-spend for alice before mining', async () => {
    const t1 = await w.send('alice', 'bob', 30n);
    expect(t1.envelope).toHaveLength(572);

    const bob = (await w.view('bob')).notes;
    expect(pick(bob)).toEqual([{ state: 'candidate', v: 30n }]);
    expect(bob[0].pos).toBeUndefined();
    expect(await w.balance('bob')).toEqual({ spendable: 0n, pending: 0n, candidate: 30n, total: 0n });

    const alice = (await w.view('alice')).notes;
    expect(pick(alice)).toEqual([
      { state: 'pending-spend', v: 100n },
      { state: 'candidate', v: 70n },
    ]);
    expect(w.wallets.alice.locks).toHaveLength(1);
    expect((await w.supplyInvariant()).perActor).toEqual({ alice: 100n, bob: 0n, carol: 0n });
  });

  it('after mining: bob confirmed(1) and spendable; alice change 70 spendable, old note spent, lock dropped', async () => {
    await w.mine(1);
    const bob = (await w.view('bob')).notes;
    expect(bob).toHaveLength(1);
    expect(bob[0]).toMatchObject({ state: 'spendable', v: 30n, confirmations: 1, source: 'transfer' });
    expect(bob[0].pos).toBeGreaterThanOrEqual(1);

    const alice = await w.view('alice');
    expect(pick(alice.notes)).toEqual([
      { state: 'spent', v: 100n },
      { state: 'spendable', v: 70n },
    ]);
    expect(alice.released.map((r) => r.reason)).toEqual(['spent']);
    expect(w.wallets.alice.locks).toHaveLength(0);
    expect((await w.supplyInvariant()).perActor).toEqual({ alice: 70n, bob: 30n, carol: 0n });
  });

  it('bob -> carol 10: final balances 70/20/10, supply invariant, accepted 2 / rejected 0', async () => {
    await w.send('bob', 'carol', 10n);
    await w.mine(1);
    const totals = await Promise.all(['alice', 'bob', 'carol'].map(async (a) => (await w.balance(a)).total));
    expect(totals).toEqual([70n, 20n, 10n]);
    for (const a of ['alice', 'bob', 'carol']) expect((await w.balance(a)).spendable).toBe((await w.balance(a)).total);
    expect((await w.supplyInvariant()).total).toBe(100n);

    const r = await w.replay();
    expect(r.acceptedCount).toBe(2);
    expect(r.rejected).toHaveLength(0);
  });

  it('a separate CLI process computes the same digest', async () => {
    const r = await w.replay();
    const res = spawnSync(path.join(REPO_ROOT, 'node_modules/.bin/tsx'), ['src/cli.ts', 'index', '--digest'], {
      cwd: REPO_ROOT,
      env: { ...process.env, ZBTC_DIR: w.zbtcDir },
      encoding: 'utf8',
      timeout: 120_000,
    });
    expect(res.status, res.stderr).toBe(0);
    const m = /digest: ([0-9a-f]{64})/.exec(res.stdout);
    expect(m?.[1]).toBe(r.digest().hex);
  });
});
