// A fixture with placeholder Bitcoin terms, for tests that never touch a node.
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { BLOCK_HASH_BYTES, TXID_BYTES } from '../../src/constants.js';
import { createFixture, type BlockSnapshot, type Fixture, type FixtureInputs } from '../../src/fixture.js';

export const TEST_SEED = sha256(utf8ToBytes('zbtc/v2/test/setup-seed'));
/** The first block after 101 mined to the miner: where the demo's funding usually lands. */
export const PLACEHOLDER_SNAPSHOT: BlockSnapshot = { blockHash: 'cc'.repeat(BLOCK_HASH_BYTES), height: 102 };
export const PLACEHOLDER_TXID = 'aa'.repeat(TXID_BYTES);
/** OP_1 PUSH32 <key>: the P2TR script shape, with a dummy output key. */
export const PLACEHOLDER_RECIPIENT_SCRIPT = hexToBytes(`5120${'bb'.repeat(32)}`);

export function testFixture(overrides: Partial<FixtureInputs> = {}): Fixture {
  return createFixture({
    seed: TEST_SEED,
    manifest: { nodeVersion: 'test', bitcoinCoreVersion: 'test' },
    snapshot: PLACEHOLDER_SNAPSHOT,
    fundingOutpoint: { txid: PLACEHOLDER_TXID, vout: 0 },
    recipientScript: PLACEHOLDER_RECIPIENT_SCRIPT,
    ...overrides,
  });
}
