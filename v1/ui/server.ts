// Demo wallet UI: a local page whose every action runs the real command-line
// tools (zbtc via tsx, bitcoin-cli, bitcoind) and streams each command line,
// with a plain-words reason for running it, as it starts and as it ends.
// ZBTC values are SIMULATED UNITS, not BTC. Page copy is Spanish.
//
// Binds to 127.0.0.1 only. Reset wipes .regtest/ and .zbtc/, the same
// demo-only directories scripts/demo.sh wipes.
import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { extractEnvelope, parse, type Envelope } from '../src/codec.js';
import {
  FIELD_BYTES,
  OFF_CM,
  OFF_CT,
  OFF_EPK,
  OFF_H_ANCHOR,
  OFF_MAGIC,
  OFF_N_IN,
  OFF_NF,
  OFF_PROOF,
  PROOF_BYTES,
} from '../src/constants.js';
import { bigIntToBytes, bytesToHex, decodeAddress, decryptNote, noteMatches } from '../src/crypto.js';
import { Wallet } from '../src/wallet.js';

const ROOT = path.resolve(import.meta.dirname, '..');
/** Where the chain and the wallets live. Tests point it at a throwaway directory. */
const STATE_DIR = path.resolve(process.env.ZBTC_UI_STATE ?? ROOT);
const DATADIR = path.join(STATE_DIR, '.regtest');
const ZBTC_DIR = path.join(STATE_DIR, '.zbtc');
const WALLETS_DIR = path.join(ZBTC_DIR, 'wallets');
/** The datadir as the command lines show it: commands run from ROOT. */
const DATADIR_ARG = path.relative(ROOT, DATADIR);
const TSX = path.join(ROOT, 'node_modules', '.bin', 'tsx');

/** The page's files, served as they are on disk so edits show on reload. */
const STATIC: Record<string, { file: string; type: string }> = {
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
  '/app.css': { file: 'app.css', type: 'text/css; charset=utf-8' },
};

const HOST = '127.0.0.1';
const HTTP_PORT = Number(process.env.PORT ?? 8543);
// Same default as scripts/demo.sh and `zbtc init`.
const RPC_PORT = Number(process.env.RPCPORT ?? 18543);

const PEOPLE = ['alice', 'bob'] as const;
type Person = (typeof PEOPLE)[number];
const GENESIS_PERSON: Person = 'alice';
const GENESIS_UNITS = 100;
/** Each fee wallet starts with 1 BTC, so a payment above this would fail on funds. */
const MAX_PAYMENT_BTC = 0.9;
const MAX_UNITS = 1_000_000;
const MAX_BODY_BYTES = 1024;
const NODE_STOP_TIMEOUT_MS = 20_000;
const NODE_STOP_POLL_MS = 200;
/** Note values are u64 little-endian in the plaintext; the leak check looks for those bytes. */
const U64_BYTES = 8;
/** How many blocks the explorer lists, newest first. */
const RECENT_BLOCKS = 8;

/** Byte ranges of the envelope fields (codec.ts layout), for the page's byte map. */
const ENVELOPE_SEGMENTS = [
  { key: 'header', offset: OFF_MAGIC, length: OFF_H_ANCHOR - OFF_MAGIC },
  { key: 'anchor', offset: OFF_H_ANCHOR, length: OFF_N_IN - OFF_H_ANCHOR },
  { key: 'counts', offset: OFF_N_IN, length: OFF_NF - OFF_N_IN },
  { key: 'nullifiers', offset: OFF_NF, length: OFF_CM - OFF_NF },
  { key: 'commitments', offset: OFF_CM, length: OFF_EPK - OFF_CM },
  { key: 'ephemeralKeys', offset: OFF_EPK, length: OFF_CT - OFF_EPK },
  { key: 'ciphertexts', offset: OFF_CT, length: OFF_PROOF - OFF_CT },
  { key: 'proof', offset: OFF_PROOF, length: PROOF_BYTES },
];

/** One executed command line. */
interface Run {
  cmd: string;
  out: string;
  ok: boolean;
}

/** What the page receives, one JSON object per line, while an action runs. */
type ActionEvent =
  | { type: 'start'; id: number; why: string; cmd: string }
  | { type: 'end'; id: number; out: string; ok: boolean }
  | { type: 'done'; ok: true; result: unknown }
  | { type: 'done'; ok: false; error: string };

type TxKind = 'coinbase' | 'transparent' | 'zbtc';

interface TxOutput {
  btc: number;
  type: string;
  address: string | null;
  /** Script hex of an OP_RETURN output; null for payments. */
  data: string | null;
}

/** What any observer of the chain sees for one transaction. */
interface PublicTx {
  txid: string;
  kind: TxKind;
  vsize: number;
  inputs: { btc: number; address: string | null }[];
  outputs: TxOutput[];
}

interface LeakCheck {
  label: string;
  inClear: boolean;
}

/** The ZBTC envelope of a shielded transfer, decoded field by field. */
interface EnvelopeView {
  vout: number;
  /** Envelope bytes as hex, without the OP_RETURN push prefix. */
  hex: string;
  segments: typeof ENVELOPE_SEGMENTS;
  anchorHeight: number;
  nullifiers: string[];
  commitments: string[];
  ephemeralKeys: string[];
  ciphertexts: string[];
  /** The 8 proof coordinates as hex: A (2), B (4), C (2), the prover.proofToBytes order. */
  proof: string[];
}

/** An envelope output that a wallet's key opens. */
interface OpenedNote {
  /** Output index inside the envelope (0 or 1). */
  index: number;
  units: number;
}

/** One transfer made from this page, as the wallets involved remember it. */
interface ActivityEntry {
  kind: 'genesis' | 'transparent' | 'shielded';
  txid: string | null;
  from: Person | null;
  to: Person;
  /** BTC for transparent, units for shielded and genesis, as entered. */
  amount: string;
  time: number;
  /** Shielded: what the recipient's key opened, and the search for leaks in the OP_RETURN. */
  opened?: OpenedNote[];
  checks?: LeakCheck[];
  /** Transparent: the address the recipient's wallet made, and the sender's input addresses. */
  recipientAddress?: string;
  senderAddresses?: string[];
}

interface NoteRow {
  /** The `zbtc notes` state label, e.g. "candidate" or "confirmed(2)". */
  state: string;
  units: number;
  height: number | null;
}

interface WalletView {
  name: Person;
  total: number;
  spendable: number;
  pending: number;
  incoming: number;
  notes: NoteRow[];
  /** The person's ordinary Bitcoin wallet, which pays fees. */
  fee: { confirmed: number; unconfirmed: number };
}

interface ChainState {
  height: number;
  bestHash: string;
  /** Transactions in the mempool, waiting for a block. */
  mempool: string[];
  accepted: number;
  rejected: number;
  digest: string;
  wallets: WalletView[];
  activity: (ActivityEntry & { pending: boolean })[];
}

class BadRequest extends Error {}

/** Raised when a command exits non-zero; its output is already streamed. */
class CommandFailed extends Error {}

/** Transfers made from this page since the last reset, newest last. */
let activity: ActivityEntry[] = [];

type CommandLine = [cmd: string, file: string, args: string[]];

function runCommand([cmd, file, args]: CommandLine): Promise<Run> {
  return new Promise((resolve) => {
    execFile(file, args, { cwd: ROOT, env: { ...process.env, FORCE_COLOR: '0', ZBTC_DIR } }, (error, stdout, stderr) => {
      resolve({ cmd, out: (stdout + stderr).trim(), ok: error === null });
    });
  });
}

function nodeArgs(): string[] {
  return ['-regtest', `-datadir=${DATADIR}`, `-rpcport=${RPC_PORT}`];
}

function zbtcLine(args: string[]): CommandLine {
  return [`zbtc ${args.join(' ')}`, TSX, ['src/cli.ts', ...args]];
}

// The node flags are hidden from the page to keep the command lines readable.
function bcliLine(args: string[]): CommandLine {
  return [`bitcoin-cli ${args.join(' ')}`, 'bitcoin-cli', [...nodeArgs(), ...args]];
}

/** Runs one action's command lines and streams each as it starts and ends. */
class Transcript {
  private nextId = 0;
  private readonly emit: (event: ActionEvent) => void;

  constructor(emit: (event: ActionEvent) => void) {
    this.emit = emit;
  }

  /** Runs a command; a non-zero exit is reported, not thrown. */
  async run(why: string, line: CommandLine): Promise<Run> {
    const id = this.nextId++;
    this.emit({ type: 'start', id, why, cmd: line[0] });
    const run = await runCommand(line);
    this.emit({ type: 'end', id, out: run.out, ok: run.ok });
    return run;
  }

  /** Shows a step the server does in-process as a finished line, so the page hides nothing. */
  note(why: string, cmd: string, out = ''): void {
    const id = this.nextId++;
    this.emit({ type: 'start', id, why, cmd });
    this.emit({ type: 'end', id, out, ok: true });
  }

  /** Runs a command and stops the action if it fails. */
  async exec(why: string, line: CommandLine): Promise<string> {
    const run = await this.run(why, line);
    if (!run.ok) throw new CommandFailed(`falló el comando ${run.cmd}`);
    return run.out;
  }

  zbtc(why: string, ...args: string[]): Promise<string> {
    return this.exec(why, zbtcLine(args));
  }

  bcli(why: string, ...args: string[]): Promise<string> {
    return this.exec(why, bcliLine(args));
  }
}

function feeWallet(person: Person): string {
  return `${person}-fee`;
}

function title(person: Person): string {
  return person[0].toUpperCase() + person.slice(1);
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Stops the node that owns DATADIR, if any, and waits for its process to exit. */
async function stopNode(t: Transcript): Promise<void> {
  const pidFile = path.join(DATADIR, 'regtest', 'bitcoind.pid');
  if (!existsSync(pidFile)) return;
  const pid = Number(readFileSync(pidFile, 'utf8'));
  await t.run('Detener el nodo de la demo anterior', bcliLine(['stop']));
  const deadline = Date.now() + NODE_STOP_TIMEOUT_MS;
  while (isAlive(pid)) {
    if (Date.now() > deadline) throw new Error(`bitcoind (pid ${pid}) no se detuvo`);
    await sleep(NODE_STOP_POLL_MS);
  }
}

function startNode(t: Transcript): Promise<string> {
  const flags = ['-daemon', '-server=1', '-txindex=1', '-fallbackfee=0.0002', '-listen=0'];
  return t.exec('Iniciar una red Bitcoin privada (regtest) en esta máquina', [
    `bitcoind -regtest -datadir=${DATADIR_ARG} -rpcport=${RPC_PORT} ${flags.join(' ')}`,
    'bitcoind',
    [...nodeArgs(), ...flags],
  ]);
}

/** Fresh chain: a new node, Alice and Bob's wallets, and Alice's genesis note. */
async function reset(t: Transcript): Promise<void> {
  activity = [];
  await stopNode(t);
  rmSync(DATADIR, { recursive: true, force: true });
  rmSync(ZBTC_DIR, { recursive: true, force: true });
  mkdirSync(DATADIR, { recursive: true });
  t.note('Borrar la cadena y las billeteras de la demo anterior', `rm -rf ${DATADIR_ARG} ${path.relative(ROOT, ZBTC_DIR)}`);
  await startNode(t);
  await t.bcli('Esperar a que el nodo responda', '-rpcwait', 'getblockcount');
  await t.zbtc(
    'Crear la billetera minera y minar 101 bloques para que sus monedas se puedan gastar',
    'init',
    '--datadir',
    DATADIR_ARG,
    '--rpcport',
    String(RPC_PORT),
  );
  for (const person of PEOPLE) {
    await t.zbtc(`Crear la billetera protegida de ${title(person)} y su fee wallet de Bitcoin con 1 BTC`, 'wallet', 'new', person);
  }
  await t.zbtc(`Darle a ${title(GENESIS_PERSON)} una nota inicial de ${GENESIS_UNITS} unidades`, 'genesis', `${GENESIS_PERSON}=${GENESIS_UNITS}`);
  await t.zbtc('Minar un bloque para confirmar la nota inicial', 'mine', '1');
  activity.push({ kind: 'genesis', txid: null, from: null, to: GENESIS_PERSON, amount: String(GENESIS_UNITS), time: Date.now() });
}

interface RawOutput {
  value: number;
  scriptPubKey: { type: string; address?: string; hex: string };
}

interface RawInput {
  txid?: string;
  vout?: number;
  coinbase?: string;
  prevout?: RawOutput;
}

interface RawTx {
  txid: string;
  vsize: number;
  vin: RawInput[];
  vout: RawOutput[];
  blockhash?: string;
  confirmations?: number;
}

interface RawBlock {
  hash: string;
  height: number;
  time: number;
  size: number;
  confirmations: number;
  previousblockhash?: string;
  nextblockhash?: string;
  tx: RawTx[];
}

function kindOf(raw: RawTx): TxKind {
  if (raw.vin[0]?.coinbase !== undefined) return 'coinbase';
  const found = extractEnvelope({ vout: raw.vout.map((o) => ({ scriptPubKey: { hex: o.scriptPubKey.hex } })) });
  return found.kind === 'envelope' ? 'zbtc' : 'transparent';
}

/** One line of a block's or the mempool's transaction list. */
function txSummary(raw: RawTx) {
  const kind = kindOf(raw);
  return {
    txid: raw.txid,
    kind,
    vsize: raw.vsize,
    inputs: raw.vin.length,
    outputs: raw.vout.length,
    // A ZBTC transfer's payment is inside the envelope; its BTC outputs are only fee change.
    btcOut: raw.vout.reduce((s, o) => s + o.value, 0),
  };
}

/** Core attaches prevout only when undo data exists, so not for mempool transactions; then read the parent. */
async function spentOutput(t: Transcript, input: RawInput): Promise<RawOutput | null> {
  if (input.coinbase !== undefined || input.txid === undefined || input.vout === undefined) return null;
  if (input.prevout) return input.prevout;
  const parent = JSON.parse(await t.bcli('Buscar la moneda que gasta esta entrada', 'getrawtransaction', input.txid, '2')) as RawTx;
  return parent.vout[input.vout];
}

async function readTx(t: Transcript, txid: string): Promise<{ tx: PublicTx; raw: RawTx; json: string }> {
  const json = await t.bcli('Leer la transacción tal como la retransmite cualquier nodo Bitcoin', 'getrawtransaction', txid, '2');
  const raw = JSON.parse(json) as RawTx;
  const inputs: PublicTx['inputs'] = [];
  for (const input of raw.vin) {
    const spent = await spentOutput(t, input);
    inputs.push({ btc: spent?.value ?? 0, address: spent?.scriptPubKey.address ?? null });
  }
  const tx: PublicTx = {
    txid: raw.txid,
    kind: kindOf(raw),
    vsize: raw.vsize,
    inputs,
    outputs: raw.vout.map((o) => ({
      btc: o.value,
      type: o.scriptPubKey.type,
      address: o.scriptPubKey.address ?? null,
      data: o.scriptPubKey.type === 'nulldata' ? o.scriptPubKey.hex : null,
    })),
  };
  return { tx, raw, json };
}

function u64LeHex(v: bigint): string {
  const b = Buffer.alloc(U64_BYTES);
  b.writeBigUInt64LE(v);
  return b.toString('hex');
}

/** Looks for the amount and the recipient's address components in the OP_RETURN bytes. */
function leakChecks(tx: PublicTx, units: string, recipient: string): LeakCheck[] {
  const data = tx.outputs.map((o) => o.data ?? '').join('');
  const { owner, pkEnc } = decodeAddress(recipient);
  const needles = [
    { label: 'amount', hex: u64LeHex(BigInt(units)) },
    { label: 'recipient owner key', hex: bytesToHex(bigIntToBytes(owner)) },
    { label: 'recipient encryption key', hex: bytesToHex(pkEnc) },
  ];
  return needles.map(({ label, hex }) => ({ label, inClear: data.includes(hex) }));
}

function readEnvelope(tx: PublicTx): { env: Envelope; vout: number; bytes: Uint8Array } {
  const found = extractEnvelope({ vout: tx.outputs.map((o) => ({ scriptPubKey: { hex: o.data ?? '' } })) });
  if (found.kind !== 'envelope') throw new BadRequest(`la transacción ${tx.txid} no tiene un sobre ZBTC`);
  const parsed = parse(found.bytes);
  if (!parsed.ok) throw new Error(`el sobre de ${tx.txid} no se puede leer: ${parsed.reason}`);
  return { env: parsed.env, vout: found.vout, bytes: found.bytes };
}

function envelopeView({ env, vout, bytes }: ReturnType<typeof readEnvelope>): EnvelopeView {
  const field = (x: bigint) => bytesToHex(bigIntToBytes(x));
  const coordinates = env.proofBytes.length / FIELD_BYTES;
  return {
    vout,
    hex: bytesToHex(bytes),
    segments: ENVELOPE_SEGMENTS,
    anchorHeight: env.hAnchor,
    nullifiers: env.nf.map(field),
    commitments: env.cm.map(field),
    ephemeralKeys: env.epk.map((k) => bytesToHex(k)),
    ciphertexts: env.ct.map((c) => bytesToHex(c)),
    proof: Array.from({ length: coordinates }, (_, i) => bytesToHex(env.proofBytes.subarray(i * FIELD_BYTES, (i + 1) * FIELD_BYTES))),
  };
}

/** Trial-decrypts each envelope output with the person's key, as the wallet's mempool scan does. */
function openedBy(env: Envelope, person: Person): OpenedNote[] {
  const { keys } = Wallet.load(WALLETS_DIR, person);
  return env.cm.flatMap((cm, index) => {
    const pt = decryptNote(keys.skEnc, env.epk[index], env.ct[index], cm);
    return pt && noteMatches(pt.v, keys.owner, pt.rseed, cm) ? [{ index, units: Number(pt.v) }] : [];
  });
}

function describeOpened(opened: OpenedNote[]): string {
  return opened.map((n) => `salida ${n.index + 1}: ${n.units} units`).join('\n') || 'ninguna salida se abre';
}

function fieldOf(output: string, name: string): string {
  const match = new RegExp(`^${name}: (\\S+)`, 'm').exec(output);
  if (!match) throw new Error(`no aparece la línea "${name}:" en la salida del comando`);
  return match[1];
}

/** Rows of the `zbtc notes` table: state, units, pos, height, nf. */
function parseNotes(output: string): NoteRow[] {
  const lines = output.split('\n').map((l) => l.trim());
  const head = lines.findIndex((l) => l.startsWith('state'));
  if (head < 0) return [];
  return lines
    .slice(head + 1)
    .filter((l) => l !== '' && l !== '(none)')
    .map((l) => {
      const [state, units, , height] = l.split(/\s+/);
      return { state, units: Number(units), height: height === '-' ? null : Number(height) };
    });
}

const BALANCE_LINE = /^(\w+): (\d+) units \(spendable (\d+), pending (\d+), incoming (\d+) not counted\)$/;

async function payTransparent(t: Transcript, from: Person, to: Person, btc: string) {
  const address = await t.bcli(`La fee wallet de ${title(to)} genera una dirección nueva para cobrar`, `-rpcwallet=${feeWallet(to)}`, 'getnewaddress');
  const txid = await t.bcli(
    `La fee wallet de ${title(from)} firma y difunde un pago Bitcoin común`,
    `-rpcwallet=${feeWallet(from)}`,
    'sendtoaddress',
    address,
    btc,
  );
  const { tx } = await readTx(t, txid);
  const entry: ActivityEntry = {
    kind: 'transparent',
    txid,
    from,
    to,
    amount: btc,
    time: Date.now(),
    recipientAddress: address,
    senderAddresses: [...new Set(tx.inputs.map((i) => i.address).filter((a) => a !== null))],
  };
  activity.push(entry);
  return entry;
}

async function sendShielded(t: Transcript, from: Person, to: Person, units: string) {
  const sent = await t.zbtc(
    `La billetera de ${title(from)} elige notas, prueba el gasto en conocimiento cero, cifra las notas nuevas y difunde una sola transacción Bitcoin`,
    'send',
    from,
    to,
    units,
  );
  const txid = fieldOf(sent, 'txid');
  const { tx } = await readTx(t, txid);
  const recipient = await t.zbtc(`Dirección ZBTC pública de ${title(to)}, para buscar sus claves en la transacción`, 'address', to);
  await t.zbtc(`La billetera de ${title(to)} intenta abrir cada nota nueva con su clave`, 'notes', to);
  const opened = openedBy(readEnvelope(tx).env, to);
  t.note(
    `Ver cuál de las dos salidas del sobre abre la clave de ${title(to)}, con el mismo descifrado que usa zbtc notes`,
    `decryptNote(clave de ${to}, salidas 1 y 2 del sobre)`,
    describeOpened(opened),
  );
  const entry: ActivityEntry = { kind: 'shielded', txid, from, to, amount: units, time: Date.now(), opened, checks: leakChecks(tx, units, recipient) };
  activity.push(entry);
  return entry;
}

/** A transaction as an explorer shows it: the public view, its block, and its decoded envelope if any. */
async function txDetail(t: Transcript, txid: string) {
  const { tx, raw, json } = await readTx(t, txid);
  let block = null;
  if (raw.blockhash) {
    const header = JSON.parse(await t.bcli('Leer el encabezado del bloque que la confirmó', 'getblockheader', raw.blockhash)) as Omit<RawBlock, 'tx' | 'size'>;
    block = { hash: header.hash, height: header.height, time: header.time, confirmations: header.confirmations };
  }
  const envelope = tx.kind === 'zbtc' ? envelopeView(readEnvelope(tx)) : null;
  return { tx, block, envelope, json, entry: activity.find((e) => e.txid === txid) ?? null };
}

/** The newest blocks with their transactions, and the mempool, for the explorer's home. */
async function recentBlocks(t: Transcript) {
  const blocks = [];
  let hash: string | undefined = await t.bcli('Hash del último bloque', 'getbestblockhash');
  for (let i = 0; i < RECENT_BLOCKS && hash; i++) {
    const b = JSON.parse(await t.bcli('Leer un bloque con sus transacciones', 'getblock', hash, '2')) as RawBlock;
    blocks.push({ hash: b.hash, height: b.height, time: b.time, size: b.size, txs: b.tx.map(txSummary) });
    hash = b.previousblockhash;
  }
  const ids = JSON.parse(await t.bcli('Transacciones que esperan un bloque (mempool)', 'getrawmempool')) as string[];
  const mempool = [];
  for (const id of ids) {
    mempool.push(txSummary(JSON.parse(await t.bcli('Leer una transacción de la mempool', 'getrawtransaction', id, '2')) as RawTx));
  }
  return { blocks, mempool };
}

/** One block for the explorer, by hash or by height. */
async function blockDetail(t: Transcript, ref: string) {
  const hash = /^\d+$/.test(ref) ? await t.bcli('Buscar el hash del bloque a esa altura', 'getblockhash', ref) : ref;
  const b = JSON.parse(await t.bcli('Leer el bloque con sus transacciones', 'getblock', hash, '2')) as RawBlock;
  return {
    hash: b.hash,
    height: b.height,
    time: b.time,
    size: b.size,
    confirmations: b.confirmations,
    previous: b.previousblockhash ?? null,
    next: b.nextblockhash ?? null,
    txs: b.tx.map(txSummary),
  };
}

async function decryptAs(t: Transcript, txid: string, person: Person) {
  const { tx } = await readTx(t, txid);
  const opened = openedBy(readEnvelope(tx).env, person);
  t.note(`Probar la clave de ${title(person)} en cada nota del sobre, como hace su billetera`, `decryptNote(clave de ${person}, salidas 1 y 2 del sobre)`, describeOpened(opened));
  return { txid, person, opened };
}

async function addresses(t: Transcript, person: Person) {
  const shielded = await t.zbtc(`Dirección ZBTC protegida de ${title(person)}`, 'address', person);
  const transparent = await t.bcli(`Dirección Bitcoin nueva de la fee wallet de ${title(person)}`, `-rpcwallet=${feeWallet(person)}`, 'getnewaddress');
  return { person, shielded, transparent };
}

interface Balances {
  mine: { trusted: number; untrusted_pending: number };
}

/** Height, mempool, replay result and each wallet's view; read-only, so the commands run in parallel. Null before the first reset. */
async function chainState(t: Transcript): Promise<ChainState | null> {
  const runs = await Promise.all([
    t.run('Hash del último bloque', bcliLine(['getbestblockhash'])),
    t.run('Transacciones esperando un bloque (mempool)', bcliLine(['getrawmempool'])),
    t.run('Reproducir toda la cadena y verificar cada prueba, como haría cualquier validador', zbtcLine(['index', '--digest'])),
    t.run('Saldo de cada billetera protegida, contado con las notas que solo ella abre', zbtcLine(['balance', ...PEOPLE])),
    ...PEOPLE.map((p) => t.run(`Notas que abre la clave de ${title(p)}`, zbtcLine(['notes', p]))),
    ...PEOPLE.map((p) => t.run(`Saldo de la fee wallet de ${title(p)}`, bcliLine([`-rpcwallet=${feeWallet(p)}`, 'getbalances']))),
  ]);
  if (!runs.every((r) => r.ok)) return null;

  const [bestHash, mempoolJson, index, balance, ...rest] = runs.map((r) => r.out);
  const notes = rest.slice(0, PEOPLE.length);
  const fees = rest.slice(PEOPLE.length).map((out) => (JSON.parse(out) as Balances).mine);
  const balances = new Map(
    balance
      .split('\n')
      .map((line) => BALANCE_LINE.exec(line.trim()))
      .filter((m) => m !== null)
      .map(([, name, total, spendable, pending, incoming]) => [name, { total, spendable, pending, incoming }]),
  );
  const wallets = PEOPLE.map((name, i) => {
    const b = balances.get(name);
    if (!b) throw new Error(`no hay línea de saldo para ${name}`);
    return {
      name,
      total: Number(b.total),
      spendable: Number(b.spendable),
      pending: Number(b.pending),
      incoming: Number(b.incoming),
      notes: parseNotes(notes[i]),
      fee: { confirmed: fees[i].trusted, unconfirmed: fees[i].untrusted_pending },
    };
  });
  const mempool = JSON.parse(mempoolJson) as string[];
  return {
    height: Number(fieldOf(index, 'height')),
    bestHash,
    mempool,
    accepted: Number(fieldOf(index, 'accepted')),
    rejected: Number(fieldOf(index, 'rejected')),
    digest: fieldOf(index, 'digest'),
    wallets,
    activity: activity.map((e) => ({ ...e, pending: e.txid !== null && mempool.includes(e.txid) })),
  };
}

// ---- Request validation ----

function person(x: unknown): Person {
  if (!PEOPLE.includes(x as Person)) throw new BadRequest(`persona desconocida: ${String(x)}`);
  return x as Person;
}

function parties(body: Record<string, unknown>): [Person, Person] {
  const from = person(body.from);
  const to = person(body.to);
  if (from === to) throw new BadRequest('el origen y el destino deben ser distintos');
  return [from, to];
}

function btcAmount(x: unknown): string {
  const s = String(x);
  if (!/^[0-9]+(\.[0-9]{1,8})?$/.test(s) || Number(s) <= 0 || Number(s) > MAX_PAYMENT_BTC) {
    throw new BadRequest(`el monto debe ser un valor en BTC mayor que 0 y hasta ${MAX_PAYMENT_BTC}: ${s}`);
  }
  return s;
}

function unitAmount(x: unknown): string {
  const s = String(x);
  if (!/^[1-9][0-9]*$/.test(s) || Number(s) > MAX_UNITS) {
    throw new BadRequest(`las unidades deben ser un entero entre 1 y ${MAX_UNITS}: ${s}`);
  }
  return s;
}

function txidParam(x: unknown): string {
  const s = String(x);
  if (!/^[0-9a-f]{64}$/.test(s)) throw new BadRequest(`txid inválido: ${s}`);
  return s;
}

function blockParam(x: unknown): string {
  const s = String(x);
  if (!/^([0-9a-f]{64}|\d{1,9})$/.test(s)) throw new BadRequest(`bloque inválido: ${s}`);
  return s;
}

// ---- HTTP ----

type Action = (t: Transcript, body: Record<string, unknown>) => Promise<unknown>;

const ACTIONS: Record<string, Action> = {
  '/api/reset': (t) => reset(t),
  '/api/mine': (t) => t.zbtc('Minar un bloque: las transacciones en espera se confirman', 'mine', '1'),
  '/api/state': (t) => chainState(t),
  '/api/transparent': (t, b) => payTransparent(t, ...parties(b), btcAmount(b.amount)),
  '/api/shielded': (t, b) => sendShielded(t, ...parties(b), unitAmount(b.amount)),
  '/api/tx': (t, b) => txDetail(t, txidParam(b.txid)),
  '/api/blocks': (t) => recentBlocks(t),
  '/api/block': (t, b) => blockDetail(t, blockParam(b.ref)),
  '/api/decrypt': (t, b) => decryptAs(t, txidParam(b.txid), person(b.person)),
  '/api/address': (t, b) => addresses(t, person(b.person)),
};

/** Actions run one at a time: concurrent CLI runs would race on the wallet files and the node. */
let queue: Promise<unknown> = Promise.resolve();

function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const next = queue.then(fn, fn);
  queue = next.catch(() => undefined);
  return next;
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  let text = '';
  for await (const chunk of req) {
    text += chunk;
    if (text.length > MAX_BODY_BYTES) throw new BadRequest('el cuerpo de la solicitud es demasiado grande');
  }
  return text ? (JSON.parse(text) as Record<string, unknown>) : {};
}

function send(res: ServerResponse, status: number, type: string, body: string): void {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' });
  res.end(body);
}

/** Streams an action as NDJSON: a start and an end event per command, then one done event. */
async function handleAction(action: Action, req: IncomingMessage, res: ServerResponse): Promise<void> {
  res.writeHead(200, { 'content-type': 'application/x-ndjson; charset=utf-8', 'cache-control': 'no-store' });
  const emit = (event: ActionEvent) => res.write(`${JSON.stringify(event)}\n`);
  try {
    const body = await readJson(req);
    const result = await serialized(() => action(new Transcript(emit), body));
    emit({ type: 'done', ok: true, result });
  } catch (e) {
    emit({ type: 'done', ok: false, error: e instanceof Error ? e.message : String(e) });
  }
  res.end();
}

/** A missing page file is a 404, not an uncaught error that would stop the server. */
function serveFile(res: ServerResponse, { file, type }: { file: string; type: string }): void {
  let body: string;
  try {
    body = readFileSync(path.join(import.meta.dirname, file), 'utf8');
  } catch {
    return send(res, 404, 'text/plain', `missing ui/${file}`);
  }
  send(res, 200, type, body);
}

const server = createServer((req, res) => {
  const url = req.url ?? '';
  const file = STATIC[url];
  if (req.method === 'GET' && file) return serveFile(res, file);
  const action = ACTIONS[url];
  if (req.method === 'POST' && action) return void handleAction(action, req, res);
  send(res, 404, 'text/plain', 'not found');
});

server.listen(HTTP_PORT, HOST, () => {
  console.log(`ZBTC UI on http://${HOST}:${HTTP_PORT} (bitcoind RPC port ${RPC_PORT})`);
});
