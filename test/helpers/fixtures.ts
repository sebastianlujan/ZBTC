// Fixtures shared by several test files.
import { readFileSync } from 'node:fs';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { CIRCUITS } from '../../src/constants.js';
import { replayOptionsFromBytes, type ReplayOptions } from '../../src/indexer.js';

/** Replay options for a genesis inventory (JSON text) and the production vkey. */
export function replayOptionsFor(genesisText: string): ReplayOptions {
  return replayOptionsFromBytes(utf8ToBytes(genesisText), new Uint8Array(readFileSync(CIRCUITS.main.vkey)));
}
