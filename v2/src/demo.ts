// The whole demo on one regtest node, as a pipeline of named steps:
//
//   startMiner → createTaprootKey → fundTaprootOutput → createRecipient →
//   freezeFixture → prepare → unlock → buildSpend → broadcastSpend →
//   observeChain → judgeSpend
//
// The setup operator (trusted) owns the Bitcoin key, funds its Taproot output
// and runs prepare. From unlock on, the spend uses only what the recipient
// recovers: the key from unlock, and the funding script re-derived from that
// key. A wrong key cannot sign for the funding output, and Core would say so.
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { FUNDING_SATS, SETUP_SEED_BYTES } from './constants.js';
import { createFixture, type Fixture, type Outpoint } from './fixture.js';
import { btcToSats, type BitcoinRpc, type MempoolAcceptResult } from './rpc.js';
import { generateSecretKey, internalKey, outputScript, tweakPublicKey, tweakSecretKey } from './taproot.js';
import { serialize, signKeyPath, txid, withWitness, type Transaction } from './transaction.js';
import { prepare, unlock, type PreparedNote } from './unlock.js';

/** Coinbase outputs mature after 100 blocks, so mining 101 makes the first one spendable. */
const MATURE_COINBASE_BLOCKS = 101;
/** One block confirms the funding and, later, the spend. */
const CONFIRMATION_BLOCKS = 1;
const MINER_WALLET = 'zbtc-v2-miner';
const RECIPIENT_WALLET = 'zbtc-v2-recipient';
/** Core's default transaction version. */
const TX_VERSION = 2;
/** Final sequence and no locktime: the spend is valid as soon as it is signed. */
const FINAL_SEQUENCE = 0xffff_ffff;
const NO_LOCKTIME = 0;
/** The spend has a single input: the funding output. */
const SPEND_INPUT = 0;

interface Miner {
  readonly wallet: BitcoinRpc;
  readonly address: string;
}

interface TaprootKey {
  readonly secretKey: Uint8Array;
  readonly script: Uint8Array;
  readonly address: string;
}

interface Recipient {
  readonly address: string;
  readonly script: Uint8Array;
}

export interface Broadcast {
  readonly rawHex: string;
  readonly localTxid: string;
  readonly coreTxid: string;
  readonly blockHash: string;
  readonly mempoolAccept: MempoolAcceptResult;
}

export interface DemoChecks {
  readonly coreDerivesFundingScript: boolean;
  readonly recoveredKeyMatchesSetup: boolean;
  readonly mempoolAccepted: boolean;
  readonly feeMatches: boolean;
  readonly coreTxidMatchesLocal: boolean;
  readonly minedTxidMatchesLocal: boolean;
  readonly spendConfirmed: boolean;
  readonly coreHexMatchesLocal: boolean;
  readonly fundingOutpointSpent: boolean;
  readonly recipientReceivedPayment: boolean;
}

export interface DemoResult {
  readonly fixture: Fixture;
  readonly prepared: PreparedNote;
  readonly fundingAddress: string;
  readonly recipientAddress: string;
  readonly broadcast: Broadcast;
  readonly confirmations: number;
  readonly checks: DemoChecks;
}

// ---- Setup operator ----

async function startMiner(rpc: BitcoinRpc): Promise<Miner> {
  await rpc.createWallet(MINER_WALLET);
  const wallet = rpc.wallet(MINER_WALLET);
  const address = await wallet.getNewAddress();
  await rpc.generateToAddress(MATURE_COINBASE_BLOCKS, address);
  return { wallet, address };
}

/** Core derives the address from rawtr(Q), so the demo never encodes bech32m itself. */
async function createTaprootKey(rpc: BitcoinRpc): Promise<TaprootKey> {
  const secretKey = generateSecretKey();
  const outputKey = tweakPublicKey(internalKey(secretKey));
  const { descriptor } = await rpc.getDescriptorInfo(`rawtr(${bytesToHex(outputKey)})`);
  const [address] = await rpc.deriveAddresses(descriptor);
  return { secretKey, script: outputScript(outputKey), address };
}

/** The funding output is found by its script, never assumed to sit at a fixed vout. */
async function fundTaprootOutput(rpc: BitcoinRpc, miner: Miner, key: TaprootKey): Promise<Outpoint> {
  const fundingTxid = await miner.wallet.sendToAddress(key.address, FUNDING_SATS);
  await rpc.generateToAddress(CONFIRMATION_BLOCKS, miner.address);
  const funding = await rpc.getRawTransaction(fundingTxid, true);
  const output = funding.vout.find(({ scriptPubKey }) => scriptPubKey.hex === bytesToHex(key.script));
  if (output === undefined) throw new Error(`funding ${fundingTxid} has no output to the Taproot key`);
  if (btcToSats(output.value) !== FUNDING_SATS) throw new Error(`funding ${fundingTxid} pays the wrong amount`);
  return { txid: fundingTxid, vout: output.n };
}

async function createRecipient(rpc: BitcoinRpc): Promise<Recipient> {
  await rpc.createWallet(RECIPIENT_WALLET);
  const address = await rpc.wallet(RECIPIENT_WALLET).getNewAddress();
  const { scriptPubKey } = await rpc.validateAddress(address);
  if (scriptPubKey === undefined) throw new Error(`Core cannot validate recipient address ${address}`);
  return { address, script: hexToBytes(scriptPubKey) };
}

async function freezeFixture(rpc: BitcoinRpc, fundingOutpoint: Outpoint, recipient: Recipient): Promise<Fixture> {
  const { subversion } = await rpc.getNetworkInfo();
  return createFixture({
    seed: randomBytes(SETUP_SEED_BYTES),
    manifest: { nodeVersion: process.versions.node, bitcoinCoreVersion: subversion },
    fundingOutpoint,
    recipientScript: recipient.script,
  });
}

// ---- Recipient ----

/** Signs with the recovered key alone; the script it spends from is re-derived from that key. */
export function buildSpend(fixture: Fixture, recoveredKey: Uint8Array): Transaction {
  const { fundingOutpoint, recipientScript, fundingSats, paymentSats } = fixture.spend;
  const unsigned: Transaction = {
    version: TX_VERSION,
    inputs: [{ ...fundingOutpoint, sequence: FINAL_SEQUENCE }],
    outputs: [{ amountSats: paymentSats, script: recipientScript }],
    locktime: NO_LOCKTIME,
  };
  const fundingScript = outputScript(tweakPublicKey(internalKey(recoveredKey)));
  const spentOutputs = [{ amountSats: fundingSats, script: fundingScript }];
  const signature = signKeyPath(unsigned, SPEND_INPUT, spentOutputs, tweakSecretKey(recoveredKey));
  return withWitness(unsigned, SPEND_INPUT, [signature]);
}

/** testmempoolaccept first, so a rejection comes back with Core's reason instead of an RPC error. */
async function broadcastSpend(rpc: BitcoinRpc, miner: Miner, spend: Transaction): Promise<Broadcast> {
  const rawHex = bytesToHex(serialize(spend));
  const [mempoolAccept] = await rpc.testMempoolAccept([rawHex]);
  if (!mempoolAccept.allowed) throw new Error(`Core rejects the spend: ${mempoolAccept['reject-reason']}`);
  const coreTxid = await rpc.sendRawTransaction(rawHex);
  const [blockHash] = await rpc.generateToAddress(CONFIRMATION_BLOCKS, miner.address);
  return { rawHex, localTxid: txid(spend), coreTxid, blockHash, mempoolAccept };
}

// ---- Verification ----

interface SpendRun {
  readonly fixture: Fixture;
  readonly fundingKey: TaprootKey;
  readonly recipient: Recipient;
  readonly recoveredKey: Uint8Array;
  readonly broadcast: Broadcast;
}

/** What Core reports after the spend is mined; judged separately so the checks stay pure. */
interface ChainEvidence {
  readonly fundingScriptHex: string | undefined;
  readonly minedTxids: readonly string[];
  readonly confirmations: number;
  readonly coreHex: string;
  readonly fundingOutputUnspent: boolean;
  readonly receivedSats: bigint;
}

async function observeChain(rpc: BitcoinRpc, run: SpendRun): Promise<ChainEvidence> {
  const { localTxid, blockHash } = run.broadcast;
  const { txid: fundingTxid, vout } = run.fixture.spend.fundingOutpoint;
  const recipientWallet = rpc.wallet(RECIPIENT_WALLET);
  return {
    fundingScriptHex: (await rpc.validateAddress(run.fundingKey.address)).scriptPubKey,
    minedTxids: (await rpc.getBlock(blockHash)).tx,
    confirmations: (await rpc.getRawTransaction(localTxid, true)).confirmations ?? 0,
    coreHex: await rpc.getRawTransaction(localTxid),
    fundingOutputUnspent: (await rpc.getTxOut(fundingTxid, vout)) !== null,
    receivedSats: btcToSats(await recipientWallet.getReceivedByAddress(run.recipient.address, CONFIRMATION_BLOCKS)),
  };
}

function judgeSpend({ fixture, fundingKey, recoveredKey, broadcast }: SpendRun, chain: ChainEvidence): DemoChecks {
  const fee = broadcast.mempoolAccept.fees?.base;
  return {
    coreDerivesFundingScript: chain.fundingScriptHex === bytesToHex(fundingKey.script),
    recoveredKeyMatchesSetup: bytesToHex(recoveredKey) === bytesToHex(fundingKey.secretKey),
    mempoolAccepted: broadcast.mempoolAccept.allowed === true,
    feeMatches: fee !== undefined && btcToSats(fee) === fixture.spend.feeSats,
    coreTxidMatchesLocal: broadcast.coreTxid === broadcast.localTxid,
    minedTxidMatchesLocal: chain.minedTxids.includes(broadcast.localTxid),
    spendConfirmed: chain.confirmations >= CONFIRMATION_BLOCKS,
    coreHexMatchesLocal: chain.coreHex === broadcast.rawHex,
    fundingOutpointSpent: !chain.fundingOutputUnspent,
    recipientReceivedPayment: chain.receivedSats === fixture.spend.paymentSats,
  };
}

export function failedChecks(checks: DemoChecks): string[] {
  return Object.entries(checks)
    .filter(([, passed]) => !passed)
    .map(([name]) => name);
}

// ---- Pipeline ----

/** Expects a fresh regtest node: it creates the miner and recipient wallets itself. */
export async function runDemo(rpc: BitcoinRpc): Promise<DemoResult> {
  const miner = await startMiner(rpc);
  const fundingKey = await createTaprootKey(rpc);
  const fundingOutpoint = await fundTaprootOutput(rpc, miner, fundingKey);
  const recipient = await createRecipient(rpc);
  const fixture = await freezeFixture(rpc, fundingOutpoint, recipient);
  const prepared = prepare(fixture, fundingKey.secretKey);
  const recoveredKey = unlock(prepared.ciphertext, prepared.envelope, prepared.witness);
  const broadcast = await broadcastSpend(rpc, miner, buildSpend(fixture, recoveredKey));
  const run: SpendRun = { fixture, fundingKey, recipient, recoveredKey, broadcast };
  const chain = await observeChain(rpc, run);
  const { address: fundingAddress } = fundingKey;
  const { address: recipientAddress } = recipient;
  const checks = judgeSpend(run, chain);
  return { fixture, prepared, fundingAddress, recipientAddress, broadcast, confirmations: chain.confirmations, checks };
}
