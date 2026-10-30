// A regtest "world": one bitcoind, a miner, shielded wallets with funded fee
// wallets, a genesis inventory and a shared incremental replay.
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { randomBytes } from '@noble/hashes/utils.js';
import { CIRCUITS } from '../../src/constants.js';
import { randomField } from '../../src/crypto.js';
import { makeGenesis, Replay, type ReplayOptions } from '../../src/indexer.js';
import { Wallet, type Balance, type TransferHooks, type TransferResult, type WalletView } from '../../src/wallet.js';
import { replayOptionsFor } from './fixtures.js';
import { fundWallet, initMiner, mine, startNode, type NodeOptions, type RegtestNode } from './regtest.js';

export interface WorldOptions {
  actors: string[];
  /** Genesis note values per actor, one note per value (actors not listed start with nothing). */
  genesis: Record<string, bigint | bigint[]>;
  /** Coins per fee wallet (several allow parallel unbroadcast carriers). Default 3. */
  feeUtxos?: number;
  /** Additional bitcoind fee wallets (e.g. "alice2-fee") with no shielded wallet. */
  extraFeeWallets?: string[];
  node?: NodeOptions;
}

export interface World {
  node: RegtestNode;
  wallets: Record<string, Wallet>;
  opts: ReplayOptions;
  /** S: first replayed height. */
  S: number;
  totalSupply: bigint;
  /** Directory with config.json + genesis.json for CLI subprocesses (ZBTC_DIR). */
  zbtcDir: string;
  feeWallet(actor: string): string;
  /** The shared replay, synced to the node's tip. */
  replay(): Promise<Replay>;
  mine(n?: number): Promise<string[]>;
  /** Mines one block with exactly these txs (raw hex or mempool txids), in order. */
  generateBlock(txs: string[]): Promise<string>;
  send(from: string, to: string, amount: bigint, hooks?: TransferHooks): Promise<TransferResult>;
  view(actor: string): Promise<WalletView>;
  balance(actor: string): Promise<Balance>;
  /** Sum of non-spent owned values (spendable + pending-spend + confirmed) the actors can detect. */
  detectedSupply(): Promise<{ total: bigint; perActor: Record<string, bigint> }>;
  /** detectedSupply() == totalSupply, or throws. */
  supplyInvariant(): Promise<{ total: bigint; perActor: Record<string, bigint> }>;
  stop(): Promise<void>;
}

export async function makeWorld(o: WorldOptions): Promise<World> {
  const node = await startNode({ txindex: true, ...o.node });
  try {
    await initMiner(node);
    const feeWallet = (a: string) => `${a}-fee`;
    for (const a of o.actors) await fundWallet(node, feeWallet(a), 1, o.feeUtxos ?? 3);
    for (const f of o.extraFeeWallets ?? []) await fundWallet(node, f, 1, o.feeUtxos ?? 3);

    const wallets: Record<string, Wallet> = {};
    for (const a of o.actors) wallets[a] = Wallet.fromSeed(randomBytes(32));

    const S = (await node.rpc.getBlockCount()) + 1;
    const entries = Object.entries(o.genesis).flatMap(([a, vs]) => {
      if (!wallets[a]) throw new Error(`genesis actor ${a} is not in actors`);
      return (Array.isArray(vs) ? vs : [vs]).map((v) => ({ v, owner: wallets[a].owner, rseed: randomField() }));
    });
    const genesisText = makeGenesis(entries, S);

    // Files a CLI subprocess can use (ZBTC_DIR=zbtcDir).
    const zbtcDir = path.join(node.datadir, 'zbtc');
    mkdirSync(zbtcDir, { recursive: true });
    const genesisPath = path.join(zbtcDir, 'genesis.json');
    writeFileSync(genesisPath, genesisText);
    writeFileSync(
      path.join(zbtcDir, 'config.json'),
      JSON.stringify(
        {
          datadir: node.datadir,
          rpcPort: node.rpcPort,
          genesisPath,
          vkeyPath: CIRCUITS.main.vkey,
          minerWallet: node.miner!.wallet,
          minerAddress: node.miner!.address,
        },
        null,
        2,
      ),
    );

    const opts = replayOptionsFor(genesisText);
    const shared = new Replay(opts);
    const replay = async () => {
      await shared.sync(node.rpc);
      return shared;
    };

    const world: World = {
      node,
      wallets,
      opts,
      S,
      totalSupply: opts.genesis.totalSupply,
      zbtcDir,
      feeWallet,
      replay,
      mine: (n = 1) => mine(node, n),
      async generateBlock(txs) {
        return (await node.rpc.generateBlock(node.miner!.address, txs)).hash;
      },
      async send(from, to, amount, hooks) {
        return wallets[from].buildTransfer({
          replay: await replay(),
          rpc: node.rpc,
          to: wallets[to].address(),
          amount,
          feeWallet: feeWallet(from),
          hooks,
        });
      },
      async view(actor) {
        return wallets[actor].view({ replay: await replay(), rpc: node.rpc });
      },
      async balance(actor) {
        return wallets[actor].balance({ replay: await replay(), rpc: node.rpc });
      },
      async detectedSupply() {
        const perActor: Record<string, bigint> = {};
        let total = 0n;
        for (const a of o.actors) {
          const { notes } = await world.view(a);
          perActor[a] = notes
            .filter((n) => n.state === 'spendable' || n.state === 'pending-spend' || n.state === 'confirmed')
            .reduce((s, n) => s + n.v, 0n);
          total += perActor[a];
        }
        return { total, perActor };
      },
      async supplyInvariant() {
        const { total, perActor } = await world.detectedSupply();
        if (total !== world.totalSupply) {
          throw new Error(`supply invariant broken: ${total} != ${world.totalSupply} (${JSON.stringify(perActor, (_, v) => (typeof v === 'bigint' ? v.toString() : v))})`);
        }
        return { total, perActor };
      },
      stop: () => node.stop(),
    };
    return world;
  } catch (e) {
    await node.stop();
    throw e;
  }
}

/** The plan's demo flow: alice -> bob 30, mine, bob -> carol 10, mine. */
export async function runAliceBobCarol(w: World): Promise<{ t1: TransferResult; t2: TransferResult }> {
  const t1 = await w.send('alice', 'bob', 30n);
  await w.mine(1);
  const t2 = await w.send('bob', 'carol', 10n);
  await w.mine(1);
  return { t1, t2 };
}
