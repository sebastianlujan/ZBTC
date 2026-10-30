// The pinned BIP341 vector subset (test/fixtures/bip341-vectors.json) and a
// decoder for its unsigned transaction, so the encoder under test is fed the
// official bytes rather than a hand-transcribed copy.
import { readFileSync } from 'node:fs';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { TXID_BYTES } from '../../src/constants.js';
import type { Transaction, TxOutput } from '../../src/transaction.js';

interface Bip341Vectors {
  readonly scriptPubKey: {
    readonly given: { readonly internalPubkey: string };
    readonly intermediary: { readonly tweak: string; readonly tweakedPubkey: string };
    readonly expected: { readonly scriptPubKey: string };
  };
  readonly keyPathSpending: {
    readonly rawUnsignedTx: string;
    readonly utxosSpent: readonly { readonly scriptPubKey: string; readonly amountSats: number }[];
    readonly inputSpending: {
      readonly given: { readonly txinIndex: number; readonly internalPrivkey: string; readonly merkleRoot: string };
      readonly intermediary: {
        readonly internalPubkey: string;
        readonly tweak: string;
        readonly tweakedPrivkey: string;
        readonly sigMsg: string;
        readonly sigHash: string;
      };
      readonly expected: { readonly witness: readonly string[] };
    };
  };
}

const VECTORS_FILE = new URL('../fixtures/bip341-vectors.json', import.meta.url);
export const BIP341: Bip341Vectors = JSON.parse(readFileSync(VECTORS_FILE, 'utf8'));

export function vectorSpentOutputs(): TxOutput[] {
  return BIP341.keyPathSpending.utxosSpent.map(({ scriptPubKey, amountSats }) => ({
    amountSats: BigInt(amountSats),
    script: hexToBytes(scriptPubKey),
  }));
}

// ---- Unsigned transaction decoder ----

const COMPACT_SIZE_U16 = 0xfd;
const COMPACT_SIZE_U32 = 0xfe;

class ByteReader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  /** A copy, so callers may reverse or view it without touching the source. */
  take(length: number): Uint8Array {
    if (this.offset + length > this.bytes.length) throw new RangeError('unexpected end of transaction');
    this.offset += length;
    return this.bytes.slice(this.offset - length, this.offset);
  }

  u32(): number {
    return new DataView(this.take(4).buffer).getUint32(0, true);
  }

  u64(): bigint {
    return new DataView(this.take(8).buffer).getBigUint64(0, true);
  }

  compactSize(): number {
    const first = this.take(1)[0];
    if (first < COMPACT_SIZE_U16) return first;
    if (first === COMPACT_SIZE_U16) return new DataView(this.take(2).buffer).getUint16(0, true);
    if (first === COMPACT_SIZE_U32) return this.u32();
    throw new RangeError('compact size above u32');
  }

  list<T>(readItem: () => T): T[] {
    return Array.from({ length: this.compactSize() }, () => readItem());
  }

  assertDone(): void {
    if (this.offset !== this.bytes.length) throw new RangeError('trailing bytes after the transaction');
  }
}

/** Legacy encoding with empty scriptSigs only, which is all an unsigned segwit transaction carries. */
export function parseUnsignedTransaction(hex: string): Transaction {
  const reader = new ByteReader(hexToBytes(hex));
  const version = reader.u32();
  const inputs = reader.list(() => {
    const txid = bytesToHex(reader.take(TXID_BYTES).reverse());
    const vout = reader.u32();
    if (reader.compactSize() !== 0) throw new RangeError('expected an empty scriptSig');
    return { txid, vout, sequence: reader.u32() };
  });
  const outputs = reader.list(() => ({ amountSats: reader.u64(), script: reader.take(reader.compactSize()) }));
  const locktime = reader.u32();
  reader.assertDone();
  return { version, inputs, outputs, locktime };
}
