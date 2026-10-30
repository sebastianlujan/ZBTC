// E2E: a REAL envelope (valid proof, real encryption, real h_body) is relayed
// as a standard transaction under bitcoind 32.1 default policy, mined, and
// recovered byte-for-byte from getblock.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { extractEnvelope, parse } from '../../src/codec.js';
import { BODY_BYTES } from '../../src/constants.js';
import { bytesToHex, decryptNote, hBody, noteMatches } from '../../src/crypto.js';
import { bytesToProof, publicSignalsOf, shutdownProver, verify } from '../../src/prover.js';
import { buildEnvelopeTx, publishEnvelope } from '../../src/rpc.js';
import { craftAliceToBob, type CraftedTransfer } from '../helpers/craft.js';
import { bob } from '../helpers/fixtures.js';
import { fundWallet, initMiner, mine, startNode, waitForHeight, type RegtestNode } from '../helpers/regtest.js';

const FEE_WALLET = 'alice-fee';

let node: RegtestNode;
let strict: RegtestNode | undefined;
let crafted: CraftedTransfer;
let root: bigint;

beforeAll(async () => {
  node = await startNode({ listen: true, txindex: true });
  await initMiner(node);
  await fundWallet(node, FEE_WALLET, 1);

  // Genesis-like note: Alice holds 100 units at position 0.
  crafted = await craftAliceToBob({ v: 100n, pay: 30n, hAnchor: await node.rpc.getBlockCount() });
  root = crafted.input.root;
});

afterAll(async () => {
  await Promise.allSettled([node?.stop(), strict?.stop()]);
  await shutdownProver();
});

describe('publish', () => {
  it('the envelope tx is standard under -acceptnonstdtxn=0 and rejected by a -datacarriersize=83 node', async () => {
    const dry = await buildEnvelopeTx(node.rpc, FEE_WALLET, crafted.bytes, { lockUnspents: false });
    const [accept] = await node.rpc.testMempoolAccept([dry.hex]);
    expect(accept['reject-reason']).toBeUndefined();
    expect(accept.allowed).toBe(true);

    // A peer with the pre-v30 data-carrier limit, synced to the same chain so
    // the inputs exist there too: only relay policy differs, not consensus.
    strict = await startNode({ connect: node.p2pPort, txindex: false, extraArgs: ['-datacarriersize=83'] });
    await waitForHeight(strict, await node.rpc.getBlockCount());
    const [rejected] = await strict.rpc.testMempoolAccept([dry.hex]);
    console.log(`[publish] -datacarriersize=83 node: allowed=${rejected.allowed} reason=${rejected['reject-reason']}`);
    expect(rejected.allowed).toBe(false);
    expect(rejected['reject-reason']).toMatch(/datacarrier/);
  });

  it('publishes, mines, and recovers the exact envelope; the proof verifies on recomputed h_body', async () => {
    const tx = await publishEnvelope(node.rpc, FEE_WALLET, crafted.bytes);
    expect(await node.rpc.getRawMempool()).toContain(tx.txid);
    const [blockHash] = await mine(node, 1);

    const block = await node.rpc.getBlock(blockHash, 2);
    const mined = block.tx.find((t) => t.txid === tx.txid);
    expect(mined).toBeDefined();

    const opReturns = mined!.vout.filter((o) => o.scriptPubKey.hex.startsWith('6a'));
    expect(opReturns).toHaveLength(1);
    const scriptHex = opReturns[0].scriptPubKey.hex;
    expect(scriptHex.startsWith('6a4d3c02')).toBe(true);
    console.log(`[publish] txid=${tx.txid} vsize=${tx.vsize} vB, OP_RETURN script=${scriptHex.length / 2} B`);

    const ext = extractEnvelope(mined!);
    expect(ext.kind).toBe('envelope');
    if (ext.kind !== 'envelope') return;
    expect(bytesToHex(ext.bytes)).toBe(bytesToHex(crafted.bytes));

    const parsed = parse(ext.bytes);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const hb = hBody(ext.bytes.subarray(0, BODY_BYTES));
    expect(hb).toBe(crafted.input.hBody);
    const signals = publicSignalsOf(root, hb, parsed.env.nf, parsed.env.cm);
    expect(await verify(signals, bytesToProof(parsed.env.proofBytes))).toBe(true);

    // The receiver can open its note from on-chain data alone.
    const note = decryptNote(bob.skEnc, parsed.env.epk[0], parsed.env.ct[0], parsed.env.cm[0]);
    expect(note).toEqual({ v: 30n, rseed: crafted.outRseed[0] });
    expect(noteMatches(note!.v, bob.owner, note!.rseed, parsed.env.cm[0])).toBe(true);
    expect(decryptNote(bob.skEnc, parsed.env.epk[1], parsed.env.ct[1], parsed.env.cm[1])).toBeNull();
  });
});
