import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { LOCK_FILE, RPC_PORT, STATE_DIR } from './env.js';

const NODE_STOP_TIMEOUT_MS = 30_000;
const NODE_STOP_POLL_MS = 250;

const cli = (...args: string[]) =>
  execFileSync('bitcoin-cli', ['-regtest', `-datadir=${path.join(STATE_DIR, '.regtest')}`, `-rpcport=${RPC_PORT}`, ...args], { stdio: 'ignore' });

/** Waits until the node no longer answers: `stop` returns at once, and the next run needs the port. */
function waitForNodeToStop(): void {
  const deadline = Date.now() + NODE_STOP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      cli('getblockcount');
    } catch {
      return;
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, NODE_STOP_POLL_MS);
  }
}

/**
 * Stops the node this run's reset started, so none outlives the run. A run that did not claim
 * the state directory (setup refused it, or never ran) leaves another run's node alone.
 */
export default function teardown(): void {
  if (!existsSync(LOCK_FILE) || Number(readFileSync(LOCK_FILE, 'utf8')) !== process.pid) return;
  try {
    cli('stop');
    waitForNodeToStop();
  } catch {
    // No node was started, or it already stopped.
  }
  rmSync(LOCK_FILE, { force: true });
}
