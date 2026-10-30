// zbtc: command-line front end (run with tsx). Values are SIMULATED UNITS of
// the shielded layer, never sats or BTC.
//
// State lives in $ZBTC_DIR (default ./.zbtc): config.json, genesis.json and
// wallets/<name>.json (seed + locks). Every command that needs the shielded
// state replays it from scratch (Replay.fresh) over the stored file bytes.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { CIRCUITS, ENVELOPE_BYTES } from './constants.js';
import { bigIntToBytes, bytesToHex, randomField } from './crypto.js';
import { makeGenesis, Replay, replayOptionsFromFiles, type RejectedEntry } from './indexer.js';
import { shutdownProver } from './prover.js';
import { BitcoinRpc, RPC_WALLET_ERROR, RpcError } from './rpc.js';
import { Wallet, type NoteView } from './wallet.js';

const ZBTC_DIR = path.resolve(process.env.ZBTC_DIR ?? '.zbtc');
const CONFIG_PATH = path.join(ZBTC_DIR, 'config.json');
const WALLETS_DIR = path.join(ZBTC_DIR, 'wallets');

const DEFAULT_DATADIR = '.regtest';
// 18543 rather than 18443: other local services often occupy the regtest default.
const DEFAULT_RPC_PORT = 18543;
const MINER_WALLET = 'miner';
/** Coinbase outputs mature after 100 blocks, so mining 101 makes the first one spendable. */
const INITIAL_BLOCKS = 101;
/** BTC sent to each new fee wallet; it pays Bitcoin fees only. */
const FEE_WALLET_FUNDING_BTC = 1;

interface Config {
  datadir: string;
  rpcPort: number;
  genesisPath: string;
  vkeyPath: string;
  minerWallet: string;
  minerAddress: string;
}

/** Path relative to the working directory, or absolute when outside it. */
function relativeToCwd(p: string): string {
  const r = path.relative(process.cwd(), p);
  return r.startsWith('..') ? p : r;
}

function loadConfig(): Config {
  if (!existsSync(CONFIG_PATH)) throw new Error(`no ${CONFIG_PATH}; run "zbtc init" first`);
  return JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) as Config;
}

function rpcOf(c: Config): BitcoinRpc {
  return new BitcoinRpc({ port: c.rpcPort, datadir: path.resolve(c.datadir) });
}

async function ensureWallet(rpc: BitcoinRpc, name: string): Promise<void> {
  try {
    await rpc.createWallet(name);
  } catch (e) {
    if (e instanceof RpcError && e.code === RPC_WALLET_ERROR) await rpc.loadWallet(name);
    else throw e;
  }
}

async function freshReplay(c: Config, rpc: BitcoinRpc): Promise<Replay> {
  return Replay.fresh(rpc, replayOptionsFromFiles(path.resolve(c.genesisPath), path.resolve(c.vkeyPath)));
}

/** Removes `name <value>` from args and returns the value. */
function takeFlag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  args.splice(i, 2);
  return v;
}

/** First 4 bytes of a field element, in hex, for display. */
function shortHex(x: bigint): string {
  return bytesToHex(bigIntToBytes(x)).slice(0, 8);
}

function feeWalletOf(name: string): string {
  return `${name}-fee`;
}

function parseUnits(s: string): bigint {
  if (!/^[0-9]+$/.test(s)) throw new Error(`amount must be a positive integer number of units: ${s}`);
  return BigInt(s);
}

function stateLabel(n: NoteView): string {
  return n.state === 'confirmed' ? `confirmed(${n.confirmations})` : n.state;
}

function noteRow(n: NoteView): string[] {
  return [
    stateLabel(n),
    n.v.toString(),
    n.pos?.toString() ?? '-',
    n.height?.toString() ?? '-',
    n.nf !== undefined ? shortHex(n.nf) : '-',
  ];
}

/** Text table lines: the first column left-aligned, the others right-aligned. */
function formatTable(head: string[], rows: string[][]): string[] {
  const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
  const line = (r: string[]) => r.map((x, i) => (i === 0 ? x.padEnd(widths[i]) : x.padStart(widths[i]))).join('  ');
  return [head, ...rows].map(line);
}

/** "CODE=count" for each rejection code, sorted by code. */
function countsByCode(rejected: readonly RejectedEntry[]): string[] {
  const counts = new Map<string, number>();
  for (const r of rejected) counts.set(r.code, (counts.get(r.code) ?? 0) + 1);
  return [...counts.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([code, n]) => `${code}=${n}`);
}

// ---- Commands ----

async function cmdInit(args: string[]): Promise<void> {
  const datadir = takeFlag(args, '--datadir') ?? DEFAULT_DATADIR;
  const rpcPort = Number(takeFlag(args, '--rpcport') ?? DEFAULT_RPC_PORT);
  const rpc = new BitcoinRpc({ port: rpcPort, datadir: path.resolve(datadir) });
  await ensureWallet(rpc, MINER_WALLET);
  const minerAddress = await rpc.wallet(MINER_WALLET).getNewAddress();
  await rpc.generateToAddress(INITIAL_BLOCKS, minerAddress);
  const config: Config = {
    datadir,
    rpcPort,
    genesisPath: relativeToCwd(path.join(ZBTC_DIR, 'genesis.json')),
    vkeyPath: relativeToCwd(CIRCUITS.main.vkey),
    minerWallet: MINER_WALLET,
    minerAddress,
  };
  mkdirSync(ZBTC_DIR, { recursive: true });
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n');
  console.log(`initialized ${relativeToCwd(CONFIG_PATH)}; height ${await rpc.getBlockCount()}`);
}

async function cmdWalletNew(name: string): Promise<void> {
  const c = loadConfig();
  const rpc = rpcOf(c);
  const w = Wallet.create(WALLETS_DIR, name);
  const fee = feeWalletOf(name);
  await ensureWallet(rpc, fee);
  await rpc.loadWallet(c.minerWallet);
  await rpc.wallet(c.minerWallet).sendToAddress(await rpc.wallet(fee).getNewAddress(), FEE_WALLET_FUNDING_BTC);
  await rpc.generateToAddress(1, c.minerAddress);
  console.log(`wallet ${name}: ${w.address()}`);
  console.log(`fee wallet ${fee}: funded with ${FEE_WALLET_FUNDING_BTC} BTC (pays Bitcoin fees only)`);
}

async function cmdGenesis(args: string[]): Promise<void> {
  const c = loadConfig();
  const rpc = rpcOf(c);
  const force = args.includes('--force');
  const specs = args.filter((a) => a !== '--force');
  if (specs.length === 0) throw new Error('usage: zbtc genesis <name>=<units> [...]');
  const genesisPath = path.resolve(c.genesisPath);
  if (existsSync(genesisPath) && !force) throw new Error(`${c.genesisPath} exists (use --force)`);
  const entries = specs.map((s) => {
    const m = /^([^=]+)=([0-9]+)$/.exec(s);
    if (!m) throw new Error(`bad genesis entry: ${s}`);
    return { v: parseUnits(m[2]), owner: Wallet.load(WALLETS_DIR, m[1]).owner, rseed: randomField() };
  });
  const S = (await rpc.getBlockCount()) + 1;
  const text = makeGenesis(entries, S);
  writeFileSync(genesisPath, text);
  const supply = entries.reduce((s, e) => s + e.v, 0n);
  console.log(`genesis: ${entries.length} notes, total supply ${supply} units, startHeight ${S} (${c.genesisPath})`);
}

async function cmdMine(n: string): Promise<void> {
  const c = loadConfig();
  const rpc = rpcOf(c);
  const count = Number(n ?? '1');
  if (!Number.isInteger(count) || count < 1) throw new Error('usage: zbtc mine <n>');
  await rpc.generateToAddress(count, c.minerAddress);
  console.log(`mined ${count}; height ${await rpc.getBlockCount()}`);
}

async function cmdSend(from: string, to: string, amountStr: string): Promise<void> {
  if (!from || !to || !amountStr) throw new Error('usage: zbtc send <from> <to-name|address> <units>');
  const c = loadConfig();
  const rpc = rpcOf(c);
  const replay = await freshReplay(c, rpc);
  const wallet = Wallet.load(WALLETS_DIR, from);
  const dest = Wallet.exists(WALLETS_DIR, to) ? Wallet.load(WALLETS_DIR, to).address() : to;
  const feeWallet = feeWalletOf(from);
  await rpc.loadWallet(feeWallet);
  const res = await wallet.buildTransfer({ replay, rpc, to: dest, amount: parseUnits(amountStr), feeWallet });
  console.log(`txid: ${res.txid}`);
  console.log(`nf: ${res.nfs.map((n) => bytesToHex(bigIntToBytes(n))).join(' ')}`);
  console.log(`anchor: ${res.anchorHeight}`);
  console.log(`envelope: ${res.envelope.length} bytes (expected ${ENVELOPE_BYTES})`);
  console.log(`vsize: ${res.vsize} vB`);
  console.log(`fee inputs (${feeWallet}): ${res.fundingOutpoints.map((o) => `${o.txid}:${o.vout}`).join(', ')}`);
}

async function cmdNotes(name: string): Promise<void> {
  const c = loadConfig();
  const rpc = rpcOf(c);
  const replay = await freshReplay(c, rpc);
  const { notes, released } = await Wallet.load(WALLETS_DIR, name).view({ replay, rpc });
  for (const r of released) console.log(`lock on ${r.txid} released: ${r.reason}`);
  console.log(`notes of ${name}:`);
  for (const line of formatTable(['state', 'units', 'pos', 'height', 'nf'], notes.map(noteRow))) console.log(line);
  if (notes.length === 0) console.log('(none)');
}

async function cmdBalance(names: string[]): Promise<void> {
  if (names.length === 0) throw new Error('usage: zbtc balance <name> [...]');
  const c = loadConfig();
  const rpc = rpcOf(c);
  const replay = await freshReplay(c, rpc);
  for (const name of names) {
    const b = await Wallet.load(WALLETS_DIR, name).balance({ replay, rpc });
    console.log(
      `${name}: ${b.total} units (spendable ${b.spendable}, pending ${b.pending}, incoming ${b.candidate} not counted)`,
    );
  }
}

async function cmdIndex(args: string[]): Promise<void> {
  const c = loadConfig();
  const rpc = rpcOf(c);
  const t0 = performance.now();
  const replay = await freshReplay(c, rpc);
  const ms = performance.now() - t0;
  const d = replay.digest();
  const codeList = countsByCode(replay.rejected);
  console.log(`height: ${d.height} (replayed from ${replay.baseHeight + 1} in ${ms.toFixed(0)} ms)`);
  console.log(`tip: ${replay.tipHash ?? '(genesis)'}`);
  console.log(`root: ${d.root}`);
  console.log(`tree size |T|: ${d.treeSize}`);
  console.log(`accepted: ${replay.acceptedCount}`);
  console.log(`rejected: ${replay.rejected.length}${codeList.length ? ` (${codeList.join(', ')})` : ''}`);
  if (args.includes('--digest')) console.log(`digest: ${d.hex}`);
}

function usage(): string {
  return [
    'usage: zbtc <command>',
    `  init [--datadir ${DEFAULT_DATADIR}] [--rpcport ${DEFAULT_RPC_PORT}]`,
    '  wallet new <name>',
    '  address <name>',
    '  genesis <name>=<units> [...] [--force]',
    '  mine <n>',
    '  send <from> <to-name|address> <units>',
    '  notes <name>',
    '  balance <name> [...]',
    '  index [--digest]',
  ].join('\n');
}

async function main(argv: string[]): Promise<void> {
  const [cmd, ...args] = argv;
  switch (cmd) {
    case 'init':
      return cmdInit(args);
    case 'wallet':
      if (args[0] !== 'new' || !args[1]) throw new Error('usage: zbtc wallet new <name>');
      return cmdWalletNew(args[1]);
    case 'address':
      if (!args[0]) throw new Error('usage: zbtc address <name>');
      console.log(Wallet.load(WALLETS_DIR, args[0]).address());
      return;
    case 'genesis':
      return cmdGenesis(args);
    case 'mine':
      return cmdMine(args[0]);
    case 'send':
      return cmdSend(args[0], args[1], args[2]);
    case 'notes':
      if (!args[0]) throw new Error('usage: zbtc notes <name>');
      return cmdNotes(args[0]);
    case 'balance':
      return cmdBalance(args);
    case 'index':
      return cmdIndex(args);
    default:
      throw new Error(usage());
  }
}

main(process.argv.slice(2))
  .catch((e: unknown) => {
    console.error(`error: ${e instanceof Error ? e.message : String(e)}`);
    process.exitCode = 1;
  })
  .finally(() => shutdownProver());
