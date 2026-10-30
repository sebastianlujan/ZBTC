// Spawns a throwaway bitcoind regtest node for e2e tests: temp datadir, free
// ports, cookie auth. Copied from v1 and trimmed to the single-node case.
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { BitcoinRpc } from '../../src/rpc.js';

export interface RegtestNode {
  readonly rpc: BitcoinRpc;
  readonly datadir: string;
  stop(): Promise<void>;
}

const BITCOIND = process.env.BITCOIND ?? 'bitcoind';
const STARTUP_TIMEOUT_MS = 60_000;
const STOP_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 100;
const DEBUG_LOG_TAIL_LINES = 30;

/** Distinct free TCP ports, held open together so they cannot collide. */
async function freePorts(count: number): Promise<number[]> {
  const servers = await Promise.all(
    Array.from(
      { length: count },
      () =>
        new Promise<net.Server>((resolve, reject) => {
          const server = net.createServer();
          server.once('error', reject);
          server.listen(0, '127.0.0.1', () => resolve(server));
        }),
    ),
  );
  const ports = servers.map((server) => (server.address() as net.AddressInfo).port);
  await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  return ports;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function debugLogTail(datadir: string): string {
  const log = path.join(datadir, 'regtest', 'debug.log');
  if (!existsSync(log)) return '(no debug.log)';
  return readFileSync(log, 'utf8').split('\n').slice(-DEBUG_LOG_TAIL_LINES).join('\n');
}

/** The same flags scripts/demo.sh uses, so the e2e run matches the demo's node. */
function bitcoindArgs(datadir: string, rpcPort: number, p2pPort: number): string[] {
  return [
    '-regtest',
    `-datadir=${datadir}`,
    '-server=1',
    '-txindex=1',
    '-fallbackfee=0.0002',
    '-acceptnonstdtxn=0',
    '-printtoconsole=0',
    '-listen=0',
    `-rpcport=${rpcPort}`,
    `-port=${p2pPort}`,
  ];
}

interface Bitcoind {
  readonly proc: ChildProcess;
  /** Resolves once the process has exited (or failed to spawn). */
  readonly exited: Promise<void>;
  hasExited(): boolean;
  stderr(): string;
}

function spawnBitcoind(args: string[]): Bitcoind {
  const proc = spawn(BITCOIND, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  proc.stderr?.on('data', (data) => (stderr += String(data)));
  let hasExited = false;
  const exited = new Promise<void>((resolve) => {
    const finish = () => {
      hasExited = true;
      resolve();
    };
    proc.once('exit', finish);
    proc.once('error', (error) => {
      stderr += String(error);
      finish();
    });
  });
  return { proc, exited, hasExited: () => hasExited, stderr: () => stderr };
}

/** Polls until bitcoind answers RPC; on exit or timeout, deletes the datadir and throws. */
async function waitUntilReady(bitcoind: Bitcoind, rpc: BitcoinRpc, datadir: string): Promise<void> {
  const cookie = path.join(datadir, 'regtest', '.cookie');
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  let lastError: unknown;
  for (;;) {
    if (bitcoind.hasExited()) {
      rmSync(datadir, { recursive: true, force: true });
      throw new Error(`bitcoind exited during startup: ${bitcoind.stderr()}\n${lastError ?? ''}`);
    }
    if (Date.now() > deadline) {
      bitcoind.proc.kill('SIGKILL');
      await bitcoind.exited;
      const tail = debugLogTail(datadir);
      rmSync(datadir, { recursive: true, force: true });
      throw new Error(`bitcoind did not become ready: ${String(lastError)}\n${tail}`);
    }
    if (existsSync(cookie)) {
      try {
        await rpc.getBlockchainInfo();
        return;
      } catch (error) {
        // ECONNREFUSED (fetch failed) or RPC -28 RPC_IN_WARMUP: retry.
        lastError = error;
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

export async function startNode(): Promise<RegtestNode> {
  const datadir = mkdtempSync(path.join(os.tmpdir(), 'zbtc-v2-regtest-'));
  const [rpcPort, p2pPort] = await freePorts(2);
  const bitcoind = spawnBitcoind(bitcoindArgs(datadir, rpcPort, p2pPort));
  const rpc = new BitcoinRpc({ port: rpcPort, datadir });
  await waitUntilReady(bitcoind, rpc, datadir);

  let stopped = false;
  return {
    rpc,
    datadir,
    async stop() {
      if (stopped) return;
      stopped = true;
      await stopBitcoind(bitcoind, rpc, datadir);
    },
  };
}
