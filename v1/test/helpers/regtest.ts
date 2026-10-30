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
const STARTUP_TIMEOUT_MS = 60_000;
const STOP_TIMEOUT_MS = 30_000;
const PEER_SYNC_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 100;
const DEBUG_LOG_TAIL_LINES = 30;
/** Coinbase outputs mature after 100 blocks, so mining 101 makes the first one spendable. */
const MATURE_COINBASE_BLOCKS = 101;

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
  return readFileSync(log, 'utf8').split('\n').slice(-DEBUG_LOG_TAIL_LINES).join('\n');
}

function bitcoindArgs(opts: NodeOptions, datadir: string, rpcPort: number, p2pPort: number): string[] {
  return [
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
}

interface Bitcoind {
  proc: ChildProcess;
  /** Resolves once the process has exited (or failed to spawn). */
  exited: Promise<void>;
  hasExited(): boolean;
  stderr(): string;
}

function spawnBitcoind(args: string[]): Bitcoind {
  const proc = spawn(BITCOIND, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  proc.stderr?.on('data', (d) => (stderr += String(d)));
  let hasExited = false;
  const exited = new Promise<void>((resolve) => {
    proc.once('exit', () => {
      hasExited = true;
      resolve();
    });
    proc.once('error', (e) => {
      stderr += String(e);
      hasExited = true;
      resolve();
    });
  });
  return { proc, exited, hasExited: () => hasExited, stderr: () => stderr };
}

/** Polls until bitcoind answers RPC; on exit or timeout, deletes the datadir and throws. */
async function waitUntilReady(bitcoind: Bitcoind, rpc: BitcoinRpc, datadir: string, timeoutMs: number): Promise<void> {
  const cookie = path.join(datadir, 'regtest', '.cookie');
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  for (;;) {
    if (bitcoind.hasExited()) {
      rmSync(datadir, { recursive: true, force: true });
      throw new Error(`bitcoind exited during startup: ${bitcoind.stderr()}\n${lastErr ?? ''}`);
    }
    if (Date.now() > deadline) {
      bitcoind.proc.kill('SIGKILL');
      await bitcoind.exited;
      const tail = debugLogTail(datadir);
      rmSync(datadir, { recursive: true, force: true });
      throw new Error(`bitcoind did not become ready: ${String(lastErr)}\n${tail}`);
    }
    if (existsSync(cookie)) {
      try {
        await rpc.getBlockchainInfo();
        return;
      } catch (e) {
        // ECONNREFUSED (fetch failed) or RPC -28 RPC_IN_WARMUP: retry.
        lastErr = e;
      }
    }
    await sleep(POLL_INTERVAL_MS);
  }
}

/** RPC stop (SIGTERM if that fails, SIGKILL after STOP_TIMEOUT_MS), then deletes the datadir. */
async function stopBitcoind(bitcoind: Bitcoind, rpc: BitcoinRpc, datadir: string): Promise<void> {
  if (!bitcoind.hasExited()) {
    try {
      await rpc.call('stop');
    } catch {
      bitcoind.proc.kill('SIGTERM');
    }
    const timedOut = await Promise.race([bitcoind.exited.then(() => false), sleep(STOP_TIMEOUT_MS).then(() => true)]);
    if (timedOut) {
      bitcoind.proc.kill('SIGKILL');
      await bitcoind.exited;
    }
  }
  rmSync(datadir, { recursive: true, force: true });
}

export async function startNode(opts: NodeOptions = {}): Promise<RegtestNode> {
  const datadir = mkdtempSync(path.join(os.tmpdir(), 'zbtc-regtest-'));
  const [rpcPort, p2pPort] = await freePorts(2);
  const bitcoind = spawnBitcoind(bitcoindArgs(opts, datadir, rpcPort, p2pPort));
  const rpc = new BitcoinRpc({ port: rpcPort, datadir });
  await waitUntilReady(bitcoind, rpc, datadir, opts.timeoutMs ?? STARTUP_TIMEOUT_MS);

  let stopped = false;
  return {
    rpc,
    datadir,
    rpcPort,
    p2pPort,
    proc: bitcoind.proc,
    async stop() {
      if (stopped) return;
      stopped = true;
      await stopBitcoind(bitcoind, rpc, datadir);
    },
  };
}

/** Creates the miner wallet and mines `blocks` (by default enough for one mature coinbase). */
export async function initMiner(node: RegtestNode, blocks = MATURE_COINBASE_BLOCKS, wallet = 'miner'): Promise<void> {
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
export async function waitForHeight(node: RegtestNode, height: number, timeoutMs = PEER_SYNC_TIMEOUT_MS): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while ((await node.rpc.getBlockCount()) < height) {
    if (Date.now() > deadline) throw new Error(`node did not reach height ${height}`);
    await sleep(POLL_INTERVAL_MS);
  }
}
