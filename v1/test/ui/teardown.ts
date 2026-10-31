import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { RPC_PORT, STATE_DIR } from './env.js';

/** The tests' reset started a bitcoind daemon; stop it so no node outlives the run. */
export default function teardown(): void {
  try {
    execFileSync('bitcoin-cli', ['-regtest', `-datadir=${path.join(STATE_DIR, '.regtest')}`, `-rpcport=${RPC_PORT}`, 'stop'], { stdio: 'ignore' });
  } catch {
    // No node was started, or it already stopped.
  }
}
