// Shielded wallet. Everything is derived from (seed, replay, mempool, locks);
// only the locks are persisted, so restoring from the seed alone recovers every
// note the wallet can decrypt (but not its outgoing payment details: there is
// no ct_out, see the deviations table in the plan).
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { randomBytes } from '@noble/hashes/utils.js';
import { envelopeHBody, extractEnvelope, parse, serialize, type Envelope } from './codec.js';
import { CT_BYTES, K_MIN, MAX_VALUE, N_IN, PROOF_BYTES, W } from './constants.js';
import {
  bytesToHex,
  cm as noteCm,
  decodeAddress,
  decryptNote,
  encodeAddress,
  encryptNote,
  hexToBytes,
  keysFromSeed,
  nf as noteNf,
  noteMatches,
  randomField,
  type Address,
  type Keys,
  type NotePlaintext,
} from './crypto.js';
import type { Replay } from './indexer.js';
import {
  buildCircuitInput,
  dummyInput,
  proofToBytes,
  prove,
  publicSignalsOf,
  verify,
  type SpendNote,
} from './prover.js';
import { buildEnvelopeTx, sendEnvelopeTx, type BitcoinRpc, type Outpoint, type RpcTx } from './rpc.js';
import { NoteTree } from './tree.js';

/** Blocks after which a lock whose carrier left the mempool is released. */
export const LOCK_EXPIRY_BLOCKS = 10;

export type NoteState = 'candidate' | 'confirmed' | 'spendable' | 'pending-spend' | 'spent';

export interface NoteView {
  state: NoteState;
  source: 'genesis' | 'transfer' | 'mempool';
  v: bigint;
  rseed: bigint;
  cm: bigint;
  /** Tree position (absent for mempool candidates). */
  pos?: number;
  /** Height of the block that created the note (S-1 for genesis notes). */
  height?: number;
  confirmations?: number;
  /** nf(sk_nf, rseed, pos), computed locally (absent for candidates). */
  nf?: bigint;
  txid?: string;
}

/** A local reservation of notes spent by a not-yet-accepted transfer. */
export interface Lock {
  /** Both envelope nullifiers (decimal). */
  nfs: string[];
  txid: string;
  /** Signed carrier, kept when it was not broadcast (noPublish). */
  carrierHex?: string;
  anchorHeight: number;
  /** R[anchorHeight] used by the proof (decimal). */
  anchorRoot: string;
  builtAtTip: number;
  fundingOutpoints: Outpoint[];
  /** bitcoind wallet holding fundingOutpoints (needed to unlock them). */
  feeWallet: string;
}

export interface LockRelease {
  txid: string;
  reason: 'spent' | 'expired' | 'needs-rebuild';
}

export interface WalletView {
  notes: NoteView[];
  released: LockRelease[];
}

export interface Balance {
  /** Notes that can be spent now. */
  spendable: bigint;
  /** Owned but not spendable now: confirmed below K, or locked by a pending spend. */
  pending: bigint;
  /** Incoming in the mempool: never counted in total. */
  candidate: bigint;
  /** spendable + pending. */
  total: bigint;
}

export interface TransferHooks {
  /** Replace the payment output's ciphertext with random bytes (bound by h_body). */
  corruptCiphertext?: boolean;
  /**
   * Put this height in the envelope instead of the tip. The proof uses the
   * tree at the nearest height that has state (clamped to [S-1, tip]), so an
   * out-of-window anchor yields an envelope that is valid except for E_ANCHOR.
   */
  anchorOverride?: number;
  /** Allow selecting notes held by a local lock (double-spend tests). */
  ignoreLocks?: boolean;
  /** Build and sign the carrier but do not broadcast it. */
  noPublish?: boolean;
  /** Choose the input notes (1 or 2) among the usable ones instead of the default policy. */
  selectNotes?: (usable: NoteView[]) => NoteView[];
}

export interface TransferRequest {
  replay: Replay;
  rpc: BitcoinRpc;
  /** Destination: a zbtcrt address string or a decoded address. */
  to: string | Address;
  amount: bigint;
  /** bitcoind wallet paying the Bitcoin fee. */
  feeWallet: string;
  hooks?: TransferHooks;
}

export interface TransferResult {
  txid: string;
  envelope: Uint8Array;
  env: Envelope;
  nfs: [bigint, bigint];
  vsize: number;
  carrierHex: string;
  fundingOutpoints: Outpoint[];
  anchorHeight: number;
  /** Index (0/1) of the payment output in the envelope; the other is change. */
  paymentIndex: number;
  /** Notes spent (excluding the dummy). */
  spent: NoteView[];
}

/** A note of ours already in the tree, before its state is derived. */
type TreeNote = Pick<NoteView, 'source' | 'v' | 'rseed' | 'cm' | 'txid'> & { pos: number; height: number };

interface WalletFile {
  seed: string;
  locks: Lock[];
}

/** Envelope bytes carried by a mempool tx, or null if it has none or left the mempool meanwhile. */
async function mempoolEnvelopeBytes(rpc: BitcoinRpc, txid: string): Promise<Uint8Array | null> {
  let tx: RpcTx;
  try {
    tx = await rpc.getRawTransaction(txid, true);
  } catch {
    return null; // left the mempool meanwhile
  }
  const extracted = extractEnvelope(tx);
  return extracted.kind === 'envelope' ? extracted.bytes : null;
}

function assertTransferAmount(amount: bigint): void {
  if (typeof amount !== 'bigint') throw new TypeError('amount must be a bigint (integer units)');
  if (amount <= 0n) throw new RangeError('amount must be > 0');
  if (amount > MAX_VALUE) throw new RangeError('amount must be < 2^64');
}

function sumValues(notes: readonly NoteView[]): bigint {
  return notes.reduce((s, n) => s + n.v, 0n);
}

/**
 * Notes that can be spent at an anchor whose tree holds `sizeAtAnchor` leaves
 * (only those have a witness there), by ascending value, then position.
 */
function usableNotes(notes: readonly NoteView[], sizeAtAnchor: number, ignoreLocks = false): NoteView[] {
  return notes
    .filter((n) => n.state === 'spendable' || (ignoreLocks && n.state === 'pending-spend'))
    .filter((n) => (n.pos as number) < sizeAtAnchor)
    .sort((a, b) => (a.v === b.v ? (a.pos as number) - (b.pos as number) : a.v < b.v ? -1 : 1));
}

/**
 * Default policy: the smallest single note covering the amount, else the two
 * largest. `usable` must be sorted as usableNotes() returns it.
 */
function selectInputs(
  usable: NoteView[],
  amount: bigint,
  selectNotes?: TransferHooks['selectNotes'],
): NoteView[] {
  if (selectNotes) {
    const chosen = selectNotes(usable);
    if (chosen.length < 1 || chosen.length > N_IN || chosen.some((n) => !usable.includes(n))) {
      throw new Error('selectNotes must return 1 or 2 of the usable notes');
    }
    return chosen;
  }
  const single = usable.find((n) => n.v >= amount);
  if (single) return [single];
  const largestTwo = usable.slice(-2);
  if (largestTwo.length < 2 || sumValues(largestTwo) < amount) {
    throw new Error(`insufficient funds: need ${amount}, spendable ${sumValues(usable)}`);
  }
  return largestTwo;
}

/**
 * Spend inputs for the selected notes, each path checked locally against
 * R[stateHeight], padded with zero-value dummies up to N_IN.
 */
function witnessedInputs(
  replay: Replay,
  selected: readonly NoteView[],
  stateHeight: number,
  root: bigint,
): SpendNote[] {
  const inputs: SpendNote[] = selected.map((n) => {
    const pos = n.pos as number;
    const merklePath = replay.witness(pos, stateHeight);
    if (NoteTree.verifyPath(n.cm, pos, merklePath) !== root) {
      throw new Error(`path of note ${pos} does not match R[${stateHeight}]`);
    }
    return { v: n.v, rseed: n.rseed, pos, path: merklePath };
  });
  while (inputs.length < N_IN) inputs.push(dummyInput());
  return inputs;
}

interface NewNote extends Address {
  v: bigint;
  rseed: bigint;
}

/** Payment and change notes with fresh rseeds, in random order. */
function shuffledOutputs(
  amount: bigint,
  dest: Address,
  change: bigint,
  self: Address,
): { outputs: NewNote[]; paymentIndex: number } {
  const outputs = [
    { v: amount, owner: dest.owner, pkEnc: dest.pkEnc, rseed: randomField() },
    { v: change, owner: self.owner, pkEnc: self.pkEnc, rseed: randomField() },
  ];
  const paymentIndex = randomBytes(1)[0] & 1;
  if (paymentIndex === 1) outputs.reverse();
  return { outputs, paymentIndex };
}

interface EnvelopePlan {
  root: bigint;
  hAnchor: number;
  skSpend: bigint;
  inputs: SpendNote[];
  outputs: NewNote[];
  /** Output whose ciphertext is replaced with random bytes (TransferHooks.corruptCiphertext). */
  corruptOutput?: number;
}

/**
 * Encrypts the outputs, binds the body through h_body and proves the
 * transfer. Throws unless the proof verifies locally for the expected public
 * signals: a wallet must never publish a proof the indexer would reject.
 */
async function proveEnvelope(plan: EnvelopePlan): Promise<Envelope> {
  const input = buildCircuitInput({
    root: plan.root,
    hBody: 0n, // placeholder: h_body depends on the body, which depends on nf/cm
    skSpend: plan.skSpend,
    inputs: plan.inputs,
    outputs: plan.outputs.map(({ v, owner, rseed }) => ({ v, owner, rseed })),
  });
  const enc = plan.outputs.map((o, k) => encryptNote({ v: o.v, rseed: o.rseed }, o.pkEnc, input.cm[k]));
  if (plan.corruptOutput !== undefined) {
    enc[plan.corruptOutput] = { ...enc[plan.corruptOutput], ct: randomBytes(CT_BYTES) };
  }
  const env: Envelope = {
    hAnchor: plan.hAnchor,
    nf: [input.nf[0], input.nf[1]],
    cm: [input.cm[0], input.cm[1]],
    epk: [enc[0].epk, enc[1].epk],
    ct: [enc[0].ct, enc[1].ct],
    proofBytes: new Uint8Array(PROOF_BYTES),
  };
  input.hBody = envelopeHBody(env);
  const { proof, publicSignals } = await prove(input);
  env.proofBytes = proofToBytes(proof);

  const signals = publicSignalsOf(plan.root, input.hBody, env.nf, env.cm);
  if (publicSignals.join() !== signals.join() || !(await verify(signals, proof))) {
    throw new Error('local proof verification failed; refusing to publish');
  }
  return env;
}

export class Wallet {
  readonly keys: Keys;
  readonly seed: Uint8Array;
  locks: Lock[];
  /** Every lock release in this process (not persisted), for observability and tests. */
  readonly releaseLog: LockRelease[] = [];
  private readonly file?: string;

  private constructor(seed: Uint8Array, locks: Lock[], file?: string) {
    this.seed = seed;
    this.keys = keysFromSeed(seed);
    this.locks = locks;
    this.file = file;
  }

  /** In-memory wallet with no locks and no file (seed recovery). */
  static fromSeed(seed: Uint8Array): Wallet {
    return new Wallet(seed.slice(), []);
  }

  /** Creates <dir>/<name>.json with a fresh 32-byte seed. Refuses to overwrite. */
  static create(dir: string, name: string): Wallet {
    const file = Wallet.pathFor(dir, name);
    if (existsSync(file)) throw new Error(`wallet ${name} already exists`);
    const w = new Wallet(randomBytes(32), [], file);
    w.save();
    return w;
  }

  static load(dir: string, name: string): Wallet {
    const file = Wallet.pathFor(dir, name);
    const data = JSON.parse(readFileSync(file, 'utf8')) as WalletFile;
    return new Wallet(hexToBytes(data.seed), data.locks ?? [], file);
  }

  static exists(dir: string, name: string): boolean {
    return existsSync(Wallet.pathFor(dir, name));
  }

  private static pathFor(dir: string, name: string): string {
    if (!/^[a-z0-9][a-z0-9_-]*$/i.test(name)) throw new Error(`invalid wallet name: ${name}`);
    return path.join(dir, `${name}.json`);
  }

  save(): void {
    if (!this.file) return;
    mkdirSync(path.dirname(this.file), { recursive: true });
    const data: WalletFile = { seed: bytesToHex(this.seed), locks: this.locks };
    writeFileSync(this.file, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
    chmodSync(this.file, 0o600);
  }

  get owner(): bigint {
    return this.keys.owner;
  }

  address(): string {
    return encodeAddress({ owner: this.keys.owner, pkEnc: this.keys.pkEnc });
  }

  // ---- Derived view ----

  private lockedNfs(): Set<string> {
    return new Set(this.locks.flatMap((l) => l.nfs));
  }

  private async unlockCoins(rpc: BitcoinRpc, lock: Lock): Promise<void> {
    // Best effort: bitcoind locks are in-memory and vanish on restart, and the
    // coins may already be spent by the carrier.
    try {
      const w = rpc.wallet(lock.feeWallet);
      const locked = await w.listLockUnspent();
      const mine = locked.filter((o) => lock.fundingOutpoints.some((f) => f.txid === o.txid && f.vout === o.vout));
      if (mine.length > 0) await w.lockUnspent(true, mine);
    } catch {
      /* ignore */
    }
  }

  /**
   * Releases locks:
   *   - any lock nf is in N -> the spend (or a copy of it) was accepted;
   *   - the anchor left the window [max(S-1, tip+1-W), tip], or R[anchor] now
   *     differs from the root the proof used -> needs rebuild. An anchor above
   *     the tip (the chain got shorter in a reorg) is undetermined: the same
   *     block may come back, so the lock is kept until the height exists again;
   *   - the carrier is not in the mempool and the tip moved > 10 blocks past it.
   */
  private async maintainLocks(replay: Replay, rpc: BitcoinRpc): Promise<LockRelease[]> {
    if (this.locks.length === 0) return [];
    const mempool = new Set(await rpc.getRawMempool());
    const tip = replay.tip;
    const released: LockRelease[] = [];
    const keep: Lock[] = [];
    for (const lock of this.locks) {
      let reason: LockRelease['reason'] | null = null;
      const a = lock.anchorHeight;
      const outOfWindow = a < replay.baseHeight || tip + 1 - a > W;
      const rootChanged = a <= tip && replay.rootAt(a)?.toString() !== lock.anchorRoot;
      if (lock.nfs.some((n) => replay.isSpent(BigInt(n)))) reason = 'spent';
      else if (outOfWindow || rootChanged) reason = 'needs-rebuild';
      else if (!mempool.has(lock.txid) && tip > lock.builtAtTip + LOCK_EXPIRY_BLOCKS) reason = 'expired';
      if (reason) {
        released.push({ txid: lock.txid, reason });
        await this.unlockCoins(rpc, lock);
      } else {
        keep.push(lock);
      }
    }
    if (released.length > 0) {
      this.releaseLog.push(...released);
      this.locks = keep;
      this.save();
    }
    return released;
  }

  /** Derived notes. Never throws on foreign or malformed data: it is skipped silently. */
  async view({ replay, rpc }: { replay: Replay; rpc: BitcoinRpc }): Promise<WalletView> {
    const released = await this.maintainLocks(replay, rpc);
    const locked = this.lockedNfs();
    const notes = [...this.genesisNotes(replay), ...this.transferNotes(replay)].map((n) =>
      this.withState(n, replay, locked),
    );
    notes.push(...(await this.mempoolCandidates(replay, rpc)));
    return { notes, released };
  }

  /** Genesis notes: plaintext inventory, matched by owner. */
  private genesisNotes(replay: Replay): TreeNote[] {
    const { owner } = this.keys;
    return replay
      .genesisOutputs()
      .filter((g) => g.owner === owner && noteCm(g.v, owner, g.rseed) === g.cm)
      .map((g) => ({ source: 'genesis', v: g.v, rseed: g.rseed, cm: g.cm, pos: g.pos, height: replay.baseHeight }));
  }

  /** Accepted transfer outputs we can decrypt. */
  private transferNotes(replay: Replay): TreeNote[] {
    const notes: TreeNote[] = [];
    for (const o of replay.outputs()) {
      const pt = this.decryptOwn(o.epk, o.ct, o.cm);
      if (!pt) continue;
      notes.push({ source: 'transfer', v: pt.v, rseed: pt.rseed, cm: o.cm, pos: o.pos, height: o.height, txid: o.txid });
    }
    return notes;
  }

  /** Adds the nullifier, confirmations and state of a note in the tree, as of the replay tip. */
  private withState(note: TreeNote, replay: Replay, locked: ReadonlySet<string>): NoteView {
    const confirmations = replay.tip - note.height + 1;
    const nf = noteNf(this.keys.skNf, note.rseed, note.pos);
    const isInTipTree = (replay.treeSizeAt(replay.tip) ?? 0) > note.pos;
    let state: NoteState = 'confirmed';
    if (replay.isSpent(nf)) state = 'spent';
    else if (locked.has(nf.toString())) state = 'pending-spend';
    else if (confirmations >= K_MIN && isInTipTree) state = 'spendable';
    return { state, ...note, confirmations, nf };
  }

  /** Mempool candidates: only envelopes that would be valid in the next block. */
  private async mempoolCandidates(replay: Replay, rpc: BitcoinRpc): Promise<NoteView[]> {
    const candidates: NoteView[] = [];
    for (const txid of await rpc.getRawMempool()) {
      const bytes = await mempoolEnvelopeBytes(rpc, txid);
      if (!bytes) continue;
      const parsed = parse(bytes);
      if (!parsed.ok) continue;
      const mine = this.ownOutputs(parsed.env, txid);
      // Validation verifies a proof: only pay for it when the envelope pays us.
      if (mine.length === 0 || !(await replay.validate(bytes, replay.tip + 1)).ok) continue;
      candidates.push(...mine);
    }
    return candidates;
  }

  private ownOutputs(env: Envelope, txid: string): NoteView[] {
    const outputs: NoteView[] = [];
    env.cm.forEach((cm, k) => {
      const pt = this.decryptOwn(env.epk[k], env.ct[k], cm);
      if (pt) outputs.push({ state: 'candidate', source: 'mempool', v: pt.v, rseed: pt.rseed, cm, txid });
    });
    return outputs;
  }

  /** Trial decryption, then the cm re-check: a plaintext is ours only if it opens cm with our owner. */
  private decryptOwn(epk: Uint8Array, ct: Uint8Array, cm: bigint): NotePlaintext | null {
    const pt = decryptNote(this.keys.skEnc, epk, ct, cm);
    return pt && noteMatches(pt.v, this.keys.owner, pt.rseed, cm) ? pt : null;
  }

  async balance(args: { replay: Replay; rpc: BitcoinRpc }): Promise<Balance> {
    return Wallet.balanceOf((await this.view(args)).notes);
  }

  static balanceOf(notes: readonly NoteView[]): Balance {
    const sum = (states: NoteState[]) => sumValues(notes.filter((n) => states.includes(n.state)));
    const spendable = sum(['spendable']);
    const pending = sum(['confirmed', 'pending-spend']);
    return { spendable, pending, candidate: sum(['candidate']), total: spendable + pending };
  }

  // ---- Spending ----

  /**
   * Builds, proves, verifies locally and (unless hooks.noPublish) broadcasts a
   * 2-in/2-out transfer, then writes a lock on its nullifiers.
   */
  async buildTransfer(req: TransferRequest): Promise<TransferResult> {
    const { replay, rpc, amount, feeWallet } = req;
    const hooks = req.hooks ?? {};
    assertTransferAmount(amount);
    const dest = typeof req.to === 'string' ? decodeAddress(req.to) : req.to;

    // Anchor: the tip by default. The proof uses the tree state at stateHeight.
    const anchorHeight = hooks.anchorOverride ?? replay.tip;
    const stateHeight = Math.min(Math.max(anchorHeight, replay.baseHeight), replay.tip);
    const sizeAtAnchor = replay.treeSizeAt(stateHeight) ?? 0;

    // 1. Select the input notes.
    const { notes } = await this.view({ replay, rpc });
    const usable = usableNotes(notes, sizeAtAnchor, hooks.ignoreLocks);
    const selected = selectInputs(usable, amount, hooks.selectNotes);
    const change = sumValues(selected) - amount;
    if (change > MAX_VALUE) throw new RangeError('change does not fit in 64 bits');

    // 2. Witnesses, checked locally against R[stateHeight].
    const root = replay.rootAt(stateHeight);
    if (root === undefined) throw new Error(`no tree state at anchor ${stateHeight}`);
    const inputs = witnessedInputs(replay, selected, stateHeight, root);

    // 3. Outputs: payment + change.
    const { outputs: outs, paymentIndex } = shuffledOutputs(amount, dest, change, this.keys);

    // 4. Encryption, body, h_body, proof (verified locally).
    const env = await proveEnvelope({
      root,
      hAnchor: anchorHeight,
      skSpend: this.keys.skSpend,
      inputs,
      outputs: outs,
      corruptOutput: hooks.corruptCiphertext ? paymentIndex : undefined,
    });
    const envelope = serialize(env);

    // 5. Refuse to publish anything the indexer would reject.
    if (hooks.anchorOverride === undefined) {
      const check = await replay.validate(envelope, replay.tip + 1);
      if (!check.ok) throw new Error(`local validation failed (${check.code}: ${check.reason}); refusing to publish`);
    }

    // 6. Carrier, broadcast, lock.
    const carrier = await buildEnvelopeTx(rpc, feeWallet, envelope);
    if (!hooks.noPublish) await sendEnvelopeTx(rpc, carrier);
    this.locks.push({
      nfs: env.nf.map((n) => n.toString()),
      txid: carrier.txid,
      ...(hooks.noPublish ? { carrierHex: carrier.hex } : {}),
      anchorHeight,
      anchorRoot: root.toString(),
      builtAtTip: replay.tip,
      fundingOutpoints: carrier.inputs,
      feeWallet,
    });
    this.save();

    return {
      txid: carrier.txid,
      envelope,
      env,
      nfs: [env.nf[0], env.nf[1]],
      vsize: carrier.vsize,
      carrierHex: carrier.hex,
      fundingOutpoints: carrier.inputs,
      anchorHeight,
      paymentIndex,
      spent: selected,
    };
  }
}
