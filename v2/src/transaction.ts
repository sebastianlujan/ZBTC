// Segwit transactions built and signed locally: serialization, txid and the
// BIP341 SIGHASH_DEFAULT digest for a Taproot key-path input.
//
// Data flow: Transaction → serializeWithoutWitness → txid (double SHA-256,
// byte-reversed). To sign: transaction + every spent output →
// signatureMessage (BIP341 SigMsg, epoch byte included) → TapSighash → BIP340
// signature, which becomes the input's only witness item. SIGHASH_DEFAULT
// commits to all inputs, all outputs and every spent amount and script, so
// any change after signing makes Core reject the spend.
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';

export interface TxInput {
  /** Display order, as Core prints it. */
  readonly txid: string;
  readonly vout: number;
  readonly sequence: number;
}

export interface TxOutput {
  readonly amountSats: bigint;
  readonly script: Uint8Array;
}

export interface Transaction {
  readonly version: number;
  readonly inputs: readonly TxInput[];
  readonly outputs: readonly TxOutput[];
  readonly locktime: number;
  /** One stack per input. Absent, or all empty, means unsigned. */
  readonly witnesses?: readonly (readonly Uint8Array[])[];
}

const U32_BYTES = 4;
const U64_BYTES = 8;
/** CompactSize prefixes for values that do not fit in one byte. */
const COMPACT_SIZE_U16 = 0xfd;
const COMPACT_SIZE_U32 = 0xfe;
const MAX_U16 = 0xffff;
const MAX_U32 = 0xffff_ffff;
/** BIP144 marker and flag: they announce that witness data follows the outputs. */
const SEGWIT_MARKER_AND_FLAG = Uint8Array.of(0x00, 0x01);
/** Segwit inputs carry their unlocking data in the witness, never in scriptSig. */
const EMPTY_SCRIPT_SIG_LENGTH = 0;

// ---- Encoding ----

function u32le(value: number): Uint8Array {
  const bytes = new Uint8Array(U32_BYTES);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}

function u64le(value: bigint): Uint8Array {
  const bytes = new Uint8Array(U64_BYTES);
  new DataView(bytes.buffer).setBigUint64(0, value, true);
  return bytes;
}

function compactSize(value: number): Uint8Array {
  if (value < COMPACT_SIZE_U16) return Uint8Array.of(value);
  if (value <= MAX_U16) return concatBytes(Uint8Array.of(COMPACT_SIZE_U16), u32le(value).slice(0, 2));
  if (value <= MAX_U32) return concatBytes(Uint8Array.of(COMPACT_SIZE_U32), u32le(value));
  throw new RangeError('compact size above u32 is not needed here');
}

function varBytes(bytes: Uint8Array): Uint8Array {
  return concatBytes(compactSize(bytes.length), bytes);
}

/** Txids are hashed in internal byte order, the reverse of how Core displays them. */
function outpointBytes({ txid, vout }: TxInput): Uint8Array {
  return concatBytes(hexToBytes(txid).reverse(), u32le(vout));
}

function inputBytes(input: TxInput): Uint8Array {
  return concatBytes(outpointBytes(input), compactSize(EMPTY_SCRIPT_SIG_LENGTH), u32le(input.sequence));
}

function outputBytes({ amountSats, script }: TxOutput): Uint8Array {
  return concatBytes(u64le(amountSats), varBytes(script));
}

function witnessBytes(stack: readonly Uint8Array[]): Uint8Array {
  return concatBytes(compactSize(stack.length), ...stack.map(varBytes));
}

// ---- Serialization ----

function inputsAndOutputs({ inputs, outputs }: Transaction): Uint8Array {
  return concatBytes(
    compactSize(inputs.length),
    ...inputs.map(inputBytes),
    compactSize(outputs.length),
    ...outputs.map(outputBytes),
  );
}

function hasWitness(tx: Transaction): boolean {
  return tx.witnesses?.some((stack) => stack.length > 0) ?? false;
}

/** The legacy encoding: what the txid hashes, whether or not the transaction is signed. */
export function serializeWithoutWitness(tx: Transaction): Uint8Array {
  return concatBytes(u32le(tx.version), inputsAndOutputs(tx), u32le(tx.locktime));
}

/** The network encoding: BIP144 when any input has a witness, legacy otherwise. */
export function serialize(tx: Transaction): Uint8Array {
  if (!hasWitness(tx)) return serializeWithoutWitness(tx);
  const witnesses = tx.inputs.map((_, index) => witnessBytes(tx.witnesses?.[index] ?? []));
  return concatBytes(u32le(tx.version), SEGWIT_MARKER_AND_FLAG, inputsAndOutputs(tx), ...witnesses, u32le(tx.locktime));
}

/** Double SHA-256 of the witness-free encoding, in display order. Signing never changes it. */
export function txid(tx: Transaction): string {
  return bytesToHex(sha256(sha256(serializeWithoutWitness(tx))).reverse());
}

/** A copy of tx with stack as the witness of one input. */
export function withWitness(tx: Transaction, inputIndex: number, stack: readonly Uint8Array[]): Transaction {
  const witnesses = tx.inputs.map((_, index) => (index === inputIndex ? stack : (tx.witnesses?.[index] ?? [])));
  return { ...tx, witnesses };
}

// ---- BIP341 signature hash ----

const TAP_SIGHASH_TAG = 'TapSighash';
const SIGHASH_EPOCH = 0x00;
/** Signs everything, and the signature carries no hash-type byte. */
const SIGHASH_DEFAULT = 0x00;
/** ext_flag = 0 (key path) and annex_present = 0. */
const KEY_PATH_SPEND_TYPE = 0x00;

function assertSigningInputs(tx: Transaction, inputIndex: number, spentOutputs: readonly TxOutput[]): void {
  if (!Number.isInteger(inputIndex) || inputIndex < 0 || inputIndex >= tx.inputs.length) {
    throw new RangeError(`input ${inputIndex} does not exist`);
  }
  if (spentOutputs.length !== tx.inputs.length) throw new RangeError('need one spent output per input');
}

function sha256Of(parts: readonly Uint8Array[]): Uint8Array {
  return sha256(concatBytes(...parts));
}

/** The epoch byte followed by SigMsg(0x00, 0), field by field in BIP341 order. */
export function signatureMessage(tx: Transaction, inputIndex: number, spentOutputs: readonly TxOutput[]): Uint8Array {
  assertSigningInputs(tx, inputIndex, spentOutputs);
  return concatBytes(
    Uint8Array.of(SIGHASH_EPOCH, SIGHASH_DEFAULT),
    u32le(tx.version),
    u32le(tx.locktime),
    sha256Of(tx.inputs.map(outpointBytes)), // sha_prevouts
    sha256Of(spentOutputs.map(({ amountSats }) => u64le(amountSats))), // sha_amounts
    sha256Of(spentOutputs.map(({ script }) => varBytes(script))), // sha_scriptpubkeys
    sha256Of(tx.inputs.map(({ sequence }) => u32le(sequence))), // sha_sequences
    sha256Of(tx.outputs.map(outputBytes)), // sha_outputs
    Uint8Array.of(KEY_PATH_SPEND_TYPE),
    u32le(inputIndex),
  );
}

export function sighashDefault(tx: Transaction, inputIndex: number, spentOutputs: readonly TxOutput[]): Uint8Array {
  return schnorr.utils.taggedHash(TAP_SIGHASH_TAG, signatureMessage(tx, inputIndex, spentOutputs));
}

/**
 * The 64-byte BIP340 signature that is the whole key-path witness. auxRand
 * defaults to fresh randomness; tests pass fixed bytes to match the vectors.
 */
export function signKeyPath(
  tx: Transaction,
  inputIndex: number,
  spentOutputs: readonly TxOutput[],
  tweakedSecretKey: Uint8Array,
  auxRand?: Uint8Array,
): Uint8Array {
  return schnorr.sign(sighashDefault(tx, inputIndex, spentOutputs), tweakedSecretKey, auxRand);
}
