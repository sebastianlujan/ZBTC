// Serialization and the BIP341 SIGHASH_DEFAULT digest against the pinned
// official key-path vector: input 4 of a 9-input, 2-output transaction.
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { internalKey, tweakPublicKey } from '../../src/taproot.js';
import {
  serialize,
  sighashDefault,
  signatureMessage,
  signKeyPath,
  txid,
  withWitness,
} from '../../src/transaction.js';
import { BIP341, parseUnsignedTransaction, vectorSpentOutputs } from '../helpers/bip341.js';

/** The vector signatures are made with 32 zero bytes of BIP340 auxiliary randomness. */
const ZERO_AUX_RAND = new Uint8Array(32);
const DUMMY_SIGNATURE = new Uint8Array(64);
/** Version (4 bytes), then the BIP144 marker and flag. */
const MARKER_AND_FLAG_OFFSET = 4;
const SEGWIT_MARKER_AND_FLAG = [0x00, 0x01];

const { rawUnsignedTx, inputSpending } = BIP341.keyPathSpending;
const { given, intermediary, expected } = inputSpending;
const tx = parseUnsignedTransaction(rawUnsignedTx);
const spentOutputs = vectorSpentOutputs();

describe('transaction encoding', () => {
  it('re-serializes the vector transaction byte for byte', () => {
    expect(bytesToHex(serialize(tx))).toBe(rawUnsignedTx);
  });

  it('switches to the BIP144 encoding once an input has a witness', () => {
    const signed = serialize(withWitness(tx, given.txinIndex, [DUMMY_SIGNATURE]));
    const markerAndFlag = signed.slice(MARKER_AND_FLAG_OFFSET, MARKER_AND_FLAG_OFFSET + 2);
    expect([...markerAndFlag]).toEqual(SEGWIT_MARKER_AND_FLAG);
  });

  it('keeps the txid when a witness is added', () => {
    expect(txid(withWitness(tx, given.txinIndex, [DUMMY_SIGNATURE]))).toBe(txid(tx));
  });
});

describe('BIP341 SIGHASH_DEFAULT key-path signing', () => {
  const tweakedSecretKey = hexToBytes(intermediary.tweakedPrivkey);

  it('builds the signature message', () => {
    expect(bytesToHex(signatureMessage(tx, given.txinIndex, spentOutputs))).toBe(intermediary.sigMsg);
  });

  it('hashes it to the expected sighash', () => {
    expect(bytesToHex(sighashDefault(tx, given.txinIndex, spentOutputs))).toBe(intermediary.sigHash);
  });

  it('signs it to the expected witness', () => {
    const signature = signKeyPath(tx, given.txinIndex, spentOutputs, tweakedSecretKey, ZERO_AUX_RAND);
    expect([bytesToHex(signature)]).toEqual(expected.witness);
  });

  it('signs with fresh randomness to a signature valid for the output key', () => {
    const outputKey = tweakPublicKey(
      internalKey(hexToBytes(given.internalPrivkey)),
      hexToBytes(given.merkleRoot),
    );
    const signature = signKeyPath(tx, given.txinIndex, spentOutputs, tweakedSecretKey);
    expect(schnorr.verify(signature, sighashDefault(tx, given.txinIndex, spentOutputs), outputKey)).toBe(true);
  });

  it('refuses spent outputs that do not match the inputs one to one', () => {
    expect(() => signatureMessage(tx, given.txinIndex, spentOutputs.slice(1))).toThrow(RangeError);
  });
});
