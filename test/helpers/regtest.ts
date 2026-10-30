// Spawns throwaway bitcoind regtest nodes for e2e tests: temp datadir, free
// ports, cookie auth. Each test file starts (and stops) its own nodes.
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { BitcoinRpc } from '../../src/rpc.js';

export interface NodeOptions {
  /** Accept inbound P2P connections (needed for a peer to -connect here). Default false. */
  listen?: boolean;
  /** -txindex. Default true. */
  txindex?: boolean;
  /** P2P port of another local node to -connect to. */
  connect?: number;
  extraArgs?: string[];
  /** Startup timeout (ms). Default 60 s. */
  timeoutMs?: number;
}

export interface RegtestNode {
  rpc: BitcoinRpc;
  datadir: string;
  rpcPort: number;
  p2pPort: number;
  proc: ChildProcess;
  /** Set by initMiner. */
  miner?: { wallet: string; address: string };
  stop(): Promise<void>;
}

const BITCOIND = process.env.BITCOIND ?? 'bitcoind';

/** Distinct free TCP ports, held open together so they cannot collide. */
async function freePorts(n: number): Promise<number[]> {
  const servers = await Promise.all(
    Array.from(
      { length: n },
      () =>
        new Promise<net.Server>((resolve, reject) => {
          const s = net.createServer();
          s.once('error', reject);
          s.listen(0, '127.0.0.1', () => resolve(s));
        }),
    ),
  );
  const ports = servers.map((s) => (s.address() as net.AddressInfo).port);
  await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  return ports;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function debugLogTail(datadir: string): string {
  const log = path.join(datadir, 'regtest', 'debug.log');
  if (!existsSync(log)) return '(no debug.log)';
  return readFileSync(log, 'utf8').split('\n').slice(-30).join('\n');
}

export async function startNode(opts: NodeOptions = {}): Promise<RegtestNode> {
  const datadir = mkdtempSync(path.join(os.tmpdir(), 'zbtc-regtest-'));
  const [rpcPort, p2pPort] = await freePorts(2);
  const args = [
    '-regtest',
    `-datadir=${datadir}`,
    '-server=1',
    '-fallbackfee=0.0002',
    '-acceptnonstdtxn=0',
    '-printtoconsole=0',
    `-rpcport=${rpcPort}`,
    `-port=${p2pPort}`,
    // bitcoind 32 refuses -bind together with -listen=0, so bind only when listening.
    ...(opts.listen ? ['-listen=1', '-bind=127.0.0.1'] : ['-listen=0']),
    `-txindex=${opts.txindex === false ? 0 : 1}`,
    ...(opts.connect !== undefined ? [`-connect=127.0.0.1:${opts.connect}`] : []),
    ...(opts.extraArgs ?? []),
  ];
  const proc = spawn(BITCOIND, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  proc.stderr?.on('data', (d) => (stderr += String(d)));
  let exited = false;
  const exitPromise = new Promise<void>((resolve) => {
    proc.once('exit', () => {
      exited = true;
      resolve();
    });
    proc.once('error', (e) => {
      stderr += String(e);
      exited = true;
      resolve();
    });
  });

  const rpc = new BitcoinRpc({ port: rpcPort, datadir });
  const cookie = path.join(datadir, 'regtest', '.cookie');
  const deadline = Date.now() + (opts.timeoutMs ?? 60_000);
  let lastErr: unknown;
  for (;;) {
    if (exited) {
      rmSync(datadir, { recursive: true, force: true });
      throw new Error(`bitcoind exited during startup: ${stderr}\n${lastErr ?? ''}`);
    }
    if (Date.now() > deadline) {
      proc.kill('SIGKILL');
      await exitPromise;
      const tail = debugLogTail(datadir);
      rmSync(datadir, { recursive: true, force: true });
      throw new Error(`bitcoind did not become ready: ${String(lastErr)}\n${tail}`);
    }
    if (existsSync(cookie)) {
      try {
        await rpc.getBlockchainInfo();
        break;
      } catch (e) {
        // ECONNREFUSED (fetch failed) or RPC -28 (warming up): retry.
        lastErr = e;
      }
    }
    await sleep(100);
  }

  let stopped = false;
  const node: RegtestNode = {
    rpc,
    datadir,
    rpcPort,
    p2pPort,
    proc,
    async stop() {
      if (stopped) return;
      stopped = true;
      if (!exited) {
        try {
          await rpc.call('stop');
        } catch {
          proc.kill('SIGTERM');
        }
        const timedOut = await Promise.race([exitPromise.then(() => false), sleep(30_000).then(() => true)]);
        if (timedOut) {
          proc.kill('SIGKILL');
          await exitPromise;
        }
      }
      rmSync(datadir, { recursive: true, force: true });
    },
  };
  return node;
}

/** Creates the miner wallet and mines `blocks` (default 101, so one coinbase is mature). */
export async function initMiner(node: RegtestNode, blocks = 101, wallet = 'miner'): Promise<void> {
  await node.rpc.createWallet(wallet);
  const address = await node.rpc.wallet(wallet).getNewAddress();
  node.miner = { wallet, address };
  if (blocks > 0) await node.rpc.generateToAddress(blocks, address);
}

/** Mines n blocks to the miner address. Returns the block hashes. */
export async function mine(node: RegtestNode, n = 1): Promise<string[]> {
  if (!node.miner) throw new Error('initMiner first');
  return node.rpc.generateToAddress(n, node.miner.address);
}

/**
 * Creates wallet `name`, sends it `btc` from the miner split into `utxos`
 * equal coins (several coins let one actor build carriers in parallel), and
 * mines 1 block.
 */
export async function fundWallet(node: RegtestNode, name: string, btc: number, utxos = 1): Promise<void> {
  if (!node.miner) throw new Error('initMiner first');
  await node.rpc.createWallet(name);
  const w = node.rpc.wallet(name);
  const amounts: Record<string, number> = {};
  for (let i = 0; i < utxos; i++) amounts[await w.getNewAddress()] = Number((btc / utxos).toFixed(8));
  await node.rpc.wallet(node.miner.wallet).call('sendmany', ['', amounts]);
  await mine(node, 1);
}

/** Waits until `node` reaches `height` (e.g. a peer syncing over P2P). */
export async function waitForHeight(node: RegtestNode, height: number, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while ((await node.rpc.getBlockCount()) < height) {
    if (Date.now() > deadline) throw new Error(`node did not reach height ${height}`);
    await sleep(100);
  }
}
