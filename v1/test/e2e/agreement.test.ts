// Client agreement: three independent replays must produce the same state
// digest and the same R[h] map:
//   1. an incremental indexer on node A that lives through a reorg;
//   2. a fresh replay on node B (-txindex=0), peered with A over P2P;
//   3. the CLI (`tsx src/cli.ts index --digest`) in a separate process, against B.
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CIRCUITS, REPO_ROOT } from '../../src/constants.js';
import { Replay } from '../../src/indexer.js';
import { shutdownProver } from '../../src/prover.js';
import { startNode, waitForHeight, type RegtestNode } from '../helpers/regtest.js';
import { makeWorld, type World } from '../helpers/world.js';

let w: World;
let B: RegtestNode;

beforeAll(async () => {
  w = await makeWorld({ actors: ['alice', 'bob', 'carol'], genesis: { alice: 100n }, node: { listen: true } });
  B = await startNode({ connect: w.node.p2pPort, txindex: false });
});

afterAll(async () => {
  await Promise.allSettled([B?.stop(), w?.stop()]);
  await shutdownProver();
});

async function waitForSameTip(timeoutMs = 30_000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const a = await w.node.rpc.getBestBlockHash();
    if ((await B.rpc.getBestBlockHash()) === a) return a;
    if (Date.now() > deadline) throw new Error('node B did not reach node A tip (is P2P peering blocked?)');
    await waitForHeight(B, await w.node.rpc.getBlockCount(), timeoutMs).catch(() => undefined);
  }
}

describe('agreement', () => {
  it('incremental (A, through a reorg), fresh (peered B, txindex=0) and CLI (B) produce identical digests and R maps', async () => {
    const inc = await w.replay(); // incremental instance, synced after every step

    await w.send('alice', 'bob', 30n);
    await w.mine(1);
    await w.replay();
    await w.send('bob', 'carol', 10n);
    const [h] = await w.mine(1);
    await w.replay();
    expect(inc.acceptedCount).toBe(2);

    // Reorg on A: drop the block with bob -> carol, extend with empty blocks,
    // then mine the carrier again from the mempool.
    await w.node.rpc.invalidateBlock(h);
    await w.generateBlock([]);
    await w.generateBlock([]);
    const mid = await w.replay();
    expect(mid.acceptedCount).toBe(1);
    await w.mine(1);
    await w.replay();
    expect(inc.acceptedCount).toBe(2);

    // Node B follows A over P2P (including the reorg).
    const tip = await waitForSameTip();
    expect(inc.tipHash).toBe(tip);
    const peers = await B.rpc.call<unknown[]>('getpeerinfo');
    expect(peers.length).toBeGreaterThan(0);

    const fresh = await Replay.fresh(B.rpc, w.opts);

    // CLI against node B, in its own process, with the same genesis and vkey files.
    const dir = path.join(B.datadir, 'zbtc');
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, 'config.json'),
      JSON.stringify({
        datadir: B.datadir,
        rpcPort: B.rpcPort,
        genesisPath: path.join(w.zbtcDir, 'genesis.json'),
        vkeyPath: CIRCUITS.main.vkey,
        minerWallet: 'none',
        minerAddress: 'none',
      }),
    );
    const cli = spawnSync(path.join(REPO_ROOT, 'node_modules/.bin/tsx'), ['src/cli.ts', 'index', '--digest'], {
      cwd: REPO_ROOT,
      env: { ...process.env, ZBTC_DIR: dir },
      encoding: 'utf8',
      timeout: 120_000,
    });
    expect(cli.status, cli.stderr).toBe(0);
    const cliDigest = /digest: ([0-9a-f]{64})/.exec(cli.stdout)?.[1];

    const d1 = inc.digest();
    const d2 = fresh.digest();
    console.log(`[agreement] height ${d1.height}, digest ${d1.hex}`);
    expect(d2).toEqual(d1);
    expect(cliDigest).toBe(d1.hex);

    // Same R[h] for every height S-1..tip.
    expect(fresh.tip).toBe(inc.tip);
    for (let x = w.S - 1; x <= inc.tip; x++) expect(fresh.rootAt(x), `R[${x}]`).toBe(inc.rootAt(x));
    expect(fresh.rejected).toEqual(inc.rejected);
  });
});
