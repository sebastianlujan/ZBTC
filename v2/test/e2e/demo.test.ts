// The whole demo against a throwaway regtest node. Every check the run makes
// must pass, and the plan's acceptance criteria are then re-asserted with
// fresh queries to Core rather than taken from the run's own report.
import { bytesToHex } from '@noble/hashes/utils.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FEE_SATS, PAYMENT_SATS } from '../../src/constants.js';
import { failedChecks, runDemo, type DemoResult } from '../../src/demo.js';
import { btcToSats } from '../../src/rpc.js';
import { startNode, type RegtestNode } from '../helpers/regtest.js';

/** The spend has one output: the payment. */
const PAYMENT_OUTPUT = 0;

describe('note-to-spend demo on regtest', () => {
  let node: RegtestNode;
  let result: DemoResult;

  beforeAll(async () => {
    node = await startNode();
    result = await runDemo(node.rpc);
  });

  afterAll(async () => {
    await node?.stop();
  });

  it('passes every check', () => {
    expect(failedChecks(result.checks)).toEqual([]);
  });

  it('gets the same txid locally, from Core and from the mined block', async () => {
    const { localTxid, coreTxid, blockHash } = result.broadcast;
    expect(coreTxid).toBe(localTxid);
    expect((await node.rpc.getBlock(blockHash)).tx).toContain(localTxid);
  });

  it('confirms the spend', async () => {
    const confirmed = await node.rpc.getRawTransaction(result.broadcast.localTxid, true);
    expect(confirmed.confirmations).toBeGreaterThanOrEqual(1);
  });

  it('pays the recipient 100,000 sats', async () => {
    const output = await node.rpc.getTxOut(result.broadcast.localTxid, PAYMENT_OUTPUT);
    expect(output?.scriptPubKey.hex).toBe(bytesToHex(result.fixture.spend.recipientScript));
    expect(output && btcToSats(output.value)).toBe(PAYMENT_SATS);
  });

  it('spends the funding outpoint', async () => {
    const { txid, vout } = result.fixture.spend.fundingOutpoint;
    expect(await node.rpc.getTxOut(txid, vout)).toBeNull();
  });

  it('leaves exactly a 1,000-sat fee', () => {
    const fee = result.broadcast.mempoolAccept.fees?.base;
    expect(fee === undefined ? undefined : btcToSats(fee)).toBe(FEE_SATS);
  });
});
