// Seed recovery: a wallet rebuilt from its seed alone (no locks file) sees the
// same notes, positions, states and balances. A sender does NOT recover the
// details of its outgoing payments (no ct_out; documented deviation).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decryptNote } from '../../src/crypto.js';
import { shutdownProver } from '../../src/prover.js';
import { Wallet, type NoteView } from '../../src/wallet.js';
import { makeWorld, runAliceBobCarol, type World } from '../helpers/world.js';

let w: World;
let flow: Awaited<ReturnType<typeof runAliceBobCarol>>;

beforeAll(async () => {
  w = await makeWorld({ actors: ['alice', 'bob', 'carol'], genesis: { alice: 100n } });
  flow = await runAliceBobCarol(w);
});

afterAll(async () => {
  await w?.stop();
  await shutdownProver();
});

const summary = (notes: NoteView[]) =>
  notes.map((n) => ({ state: n.state, v: n.v, pos: n.pos, height: n.height, nf: n.nf, cm: n.cm, rseed: n.rseed }));

async function recovered(actor: string) {
  const r = await w.replay();
  const fresh = Wallet.fromSeed(w.wallets[actor].seed);
  expect(fresh.locks).toHaveLength(0);
  return { wallet: fresh, view: await fresh.view({ replay: r, rpc: w.node.rpc }) };
}

describe('recovery from seed', () => {
  it('bob and carol: identical notes, positions, states and balances', async () => {
    for (const actor of ['bob', 'carol']) {
      const original = await w.view(actor);
      const { wallet, view } = await recovered(actor);
      expect(summary(view.notes)).toEqual(summary(original.notes));
      expect(Wallet.balanceOf(view.notes)).toEqual(await w.balance(actor));
      expect(wallet.address()).toBe(w.wallets[actor].address());
    }
    expect(Wallet.balanceOf((await recovered('bob')).view.notes).total).toBe(20n);
    expect(Wallet.balanceOf((await recovered('carol')).view.notes).total).toBe(10n);
  });

  it('alice: recovers her spent genesis note and her change, but not her outgoing payment', async () => {
    const { view } = await recovered('alice');
    expect(view.notes.map((n) => ({ state: n.state, v: n.v, source: n.source }))).toEqual([
      { state: 'spent', v: 100n, source: 'genesis' },
      { state: 'spendable', v: 70n, source: 'transfer' },
    ]);
    // The payment output to Bob is on-chain but encrypted to Bob only: from the
    // seed alone Alice cannot tell the amount (30) or the recipient.
    const pay = flow.t1.env;
    const k = flow.t1.paymentIndex;
    expect(decryptNote(w.wallets.alice.keys.skEnc, pay.epk[k], pay.ct[k], pay.cm[k])).toBeNull();
    expect(decryptNote(w.wallets.bob.keys.skEnc, pay.epk[k], pay.ct[k], pay.cm[k])?.v).toBe(30n);
    expect(view.notes.some((n) => n.v === 30n)).toBe(false);
  });
});
