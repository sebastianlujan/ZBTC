import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { LOCK_FILE, STATE_DIR } from './env.js';

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Claims the tests' state directory for this run. Two runs at once would share one node: the
 * second one's teardown would stop the first one's node mid-test.
 */
export default function setup(): void {
  mkdirSync(STATE_DIR, { recursive: true });
  if (existsSync(LOCK_FILE)) {
    const pid = Number(readFileSync(LOCK_FILE, 'utf8'));
    if (pid !== process.pid && isAlive(pid)) throw new Error(`another UI test run (pid ${pid}) is using ${STATE_DIR}; wait for it to finish`);
  }
  writeFileSync(LOCK_FILE, String(process.pid));
}
