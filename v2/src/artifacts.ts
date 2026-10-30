// Writes one run's artifacts to a directory (v2/.demo for `pnpm demo`):
//
//   fixture.json    the frozen fixture, setup side (seed and note opening included)
//   witness.json    the R04 assignment, in canonical coordinate order
//   ciphertext.bin  Mhat_0..Mhat_n as dense 32-byte big-endian entries, row-major
//   envelope.json   nonce, AEAD ciphertext and associated data, as hex
//   result.json     txids, the raw spend, the cofactor, sizes and every check
//
// The Bitcoin secret key is never written, recovered or not.
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { ciphertextBytes, type Ciphertext } from './aadp.js';
import { failedChecks, type DemoResult } from './demo.js';
import { encodeFieldElement } from './field.js';
import { serializeFixture } from './fixture.js';
import { formatJson } from './json.js';
import type { NoteEnvelope } from './unlock.js';

/** The dense encoding whose size the spec forecasts: (n+1)·k²·32 bytes. */
export function encodeCiphertext({ matrices }: Ciphertext): Uint8Array {
  return concatBytes(...matrices.flatMap((matrix) => matrix.flatMap((row) => row.map(encodeFieldElement))));
}

function envelopeJson({ sealed, associatedData }: NoteEnvelope): object {
  return {
    nonce: bytesToHex(sealed.nonce),
    ciphertext: bytesToHex(sealed.ciphertext),
    associatedData: bytesToHex(associatedData),
  };
}

function resultJson({ fixture, prepared, broadcast, checks, ...run }: DemoResult): object {
  const { fundingOutpoint, paymentSats, feeSats } = fixture.spend;
  return {
    passed: failedChecks(checks).length === 0,
    checks,
    spend: {
      localTxid: broadcast.localTxid,
      coreTxid: broadcast.coreTxid,
      blockHash: broadcast.blockHash,
      confirmations: run.confirmations,
      rawHex: broadcast.rawHex,
      fundingOutpoint,
      fundingAddress: run.fundingAddress,
      recipientAddress: run.recipientAddress,
      paymentSats: `${paymentSats}`,
      feeSats: `${feeSats}`,
    },
    aadp: {
      setupAttempt: prepared.setupAttempt,
      cofactor: `${prepared.cofactor}`,
      ciphertextBytes: ciphertextBytes(prepared.ciphertext),
    },
  };
}

export function writeArtifacts(directory: string, result: DemoResult): void {
  mkdirSync(directory, { recursive: true });
  const write = (name: string, contents: string | Uint8Array) => writeFileSync(path.join(directory, name), contents);
  write('fixture.json', serializeFixture(result.fixture));
  write('witness.json', formatJson(result.prepared.witness.map((value) => `${value}`)));
  write('ciphertext.bin', encodeCiphertext(result.prepared.ciphertext));
  write('envelope.json', formatJson(envelopeJson(result.prepared.envelope)));
  write('result.json', formatJson(resultJson(result)));
}
