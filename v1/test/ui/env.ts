// Ports and state for the UI tests. They differ from the demo's (8543, 18543, ./.regtest)
// so a test run never touches a demo someone is using.
import path from 'node:path';

export const HTTP_PORT = 8743;
export const RPC_PORT = 18743;
export const STATE_DIR = path.resolve(import.meta.dirname, '../../.ui-test');
/** Holds the pid of the run that owns STATE_DIR and its node. */
export const LOCK_FILE = path.join(STATE_DIR, 'run.lock');
