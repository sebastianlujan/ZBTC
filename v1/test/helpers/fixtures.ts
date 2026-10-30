// Fixtures shared by several test files.
import { readFileSync } from 'node:fs';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { CIRCUITS } from '../../src/constants.js';
import { keysFromSeed } from '../../src/crypto.js';
import { replayOptionsFromBytes, type ReplayOptions } from '../../src/indexer.js';

/** Fixed seeds, so every run derives the same keys. */
export const alice = keysFromSeed(new Uint8Array(32).fill(0xa1));
export const bob = keysFromSeed(new Uint8Array(32).fill(0xb0));

/** Replay options for a genesis inventory (JSON text) and the production vkey. */
export function replayOptionsFor(genesisText: string): ReplayOptions {
  return replayOptionsFromBytes(utf8ToBytes(genesisText), new Uint8Array(readFileSync(CIRCUITS.main.vkey)));
}
