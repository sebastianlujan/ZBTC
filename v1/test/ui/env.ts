// Ports and state for the UI tests. They differ from the demo's (8543, 18543, ./.regtest)
// so a test run never touches a demo someone is using.
import os from 'node:os';
import path from 'node:path';

export const HTTP_PORT = 8743;
export const RPC_PORT = 18743;
export const STATE_DIR = path.resolve(import.meta.dirname, '../../.ui-test');
/**
 * Holds the pid of the run that owns the test ports. It lives in the system temp directory, not
 * in STATE_DIR, so runs from different checkouts of the repo also keep out of each other's way.
 */
export const LOCK_FILE = path.join(os.tmpdir(), `zbtc-ui-test-${HTTP_PORT}.lock`);
