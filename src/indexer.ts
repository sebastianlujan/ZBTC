// Deterministic replay of the shielded state from Bitcoin blocks (paper §15,
// A.7). There is no database: the state is whatever replaying the active chain
// from the genesis inventory produces. Per-block undo records exist only so a
// long-running instance can follow reorgs without replaying from scratch.
//
// Determinism rules: replay reads only blocks (never the mempool or the
// clock), processes transactions in block order, and the digest never depends
// on Map/Set iteration order (everything hashed is ordered explicitly).
import { readFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { extractEnvelope, parse, type Envelope, type Extracted, type TxLike } from './codec.js';
import { BODY_BYTES, CIRCUITS, DEPTH, K_MIN, MAX_LEAVES, MAX_VALUE, W } from './constants.js';
import { bigIntToBytes, bytesToHex, cm, hBody, hexToBytes, isField } from './crypto.js';
import { bytesToProof, publicSignalsOf, verifyWithVkey, type VerificationKey } from './prover.js';
import { RPC_INVALID_ADDRESS_OR_KEY, RPC_INVALID_PARAMETER, RpcError, type BitcoinRpc } from './rpc.js';
import { NoteTree } from './tree.js';

// ---- Genesis inventory ----

export interface GenesisNote {
  v: bigint;
  owner: bigint;
  rseed: bigint;
}

export interface Genesis {
  version: 1;
  /** S: first block height whose transactions are replayed. R[S-1] is the genesis root. */
  startHeight: number;
  totalSupply: bigint;
  /** In file order; note i sits at tree position i. */
  notes: (GenesisNote & { cm: bigint })[];
}

const DEC = /^(0|[1-9][0-9]*)$/;

function decField(x: unknown, what: string): bigint {
  if (typeof x !== 'string' || !DEC.test(x)) throw new Error(`genesis: ${what} must be a canonical decimal string`);
  return BigInt(x);
}

export function cmOfGenesisNote(n: GenesisNote): bigint {
  return cm(n.v, n.owner, n.rseed);
}

/**
 * Validates a genesis inventory (JSON text or parsed object): version 1,
 * startHeight >= 1, every v < 2^64, owner and rseed < r, sum(v) == totalSupply.
 * Computes each cm in file order.
 */
export function loadGenesis(json: string | unknown): Genesis {
  const g = (typeof json === 'string' ? JSON.parse(json) : json) as Record<string, unknown>;
  if (!g || typeof g !== 'object') throw new Error('genesis: not an object');
  if (g.version !== 1) throw new Error('genesis: version must be 1');
  const S = g.startHeight;
  if (typeof S !== 'number' || !Number.isInteger(S) || S < 1 || S > 0xffffffff) {
    throw new Error('genesis: startHeight must be an integer >= 1');
  }
  const totalSupply = decField(g.totalSupply, 'totalSupply');
  if (!Array.isArray(g.notes)) throw new Error('genesis: notes must be an array');
  if (g.notes.length > MAX_LEAVES) throw new Error('genesis: too many notes');
  let sum = 0n;
  const notes = g.notes.map((raw: unknown, i: number) => {
    const n = raw as Record<string, unknown>;
    const v = decField(n?.v, `notes[${i}].v`);
    const owner = decField(n?.owner, `notes[${i}].owner`);
    const rseed = decField(n?.rseed, `notes[${i}].rseed`);
    if (v > MAX_VALUE) throw new Error(`genesis: notes[${i}].v >= 2^64`);
    if (!isField(owner)) throw new Error(`genesis: notes[${i}].owner >= r`);
    if (!isField(rseed)) throw new Error(`genesis: notes[${i}].rseed >= r`);
    sum += v;
    return { v, owner, rseed, cm: cmOfGenesisNote({ v, owner, rseed }) };
  });
  if (sum !== totalSupply) throw new Error(`genesis: sum(v) = ${sum} != totalSupply = ${totalSupply}`);
  return { version: 1, startHeight: S, totalSupply, notes };
}

/** Serializes a genesis inventory (totalSupply = sum of v). */
export function makeGenesis(entries: readonly GenesisNote[], startHeight: number): string {
  const totalSupply = entries.reduce((s, e) => s + e.v, 0n);
  const doc = {
    version: 1,
    startHeight,
    totalSupply: totalSupply.toString(),
    notes: entries.map((e) => ({ v: e.v.toString(), owner: e.owner.toString(), rseed: e.rseed.toString() })),
  };
  const text = JSON.stringify(doc, null, 2) + '\n';
  loadGenesis(text); // fail fast on invalid entries
  return text;
}

// ---- Replay state ----

export type RejectCode = 'E_MULTI' | 'E_PARSE' | 'E_ANCHOR' | 'E_NF_DUP' | 'E_NF_SPENT' | 'E_PROOF' | 'E_TREE_FULL';

type ValidEnvelope = { ok: true; env: Envelope; hBody: bigint };
type Rejection = { ok: false; code: RejectCode; reason: string };

export type Validation =
  | ValidEnvelope
  | Rejection
  | { ok: false; code: 'NONE'; reason: string };

function reject(code: RejectCode, reason: string): Rejection {
  return { ok: false, code, reason };
}

export interface AcceptedOutput {
  pos: number;
  cm: bigint;
  epk: Uint8Array;
  ct: Uint8Array;
}

export interface AcceptedEntry {
  height: number;
  txIndex: number;
  txid: string;
  hAnchor: number;
  hBody: bigint;
  nfs: [bigint, bigint];
  outputs: [AcceptedOutput, AcceptedOutput];
}

export interface RejectedEntry {
  height: number;
  txIndex: number;
  txid: string;
  code: RejectCode;
  reason: string;
}

/** An accepted transfer output, flattened for wallet scanning. */
export interface ScannableOutput extends AcceptedOutput {
  height: number;
  txid: string;
  /** Index of this output in its envelope (0 or 1). */
  index: number;
}

type BlockTx = TxLike & { txid: string };

/** The subset of `getblock <hash> 2` that replay reads. */
export interface BlockLike {
  hash: string;
  height?: number;
  previousblockhash?: string;
  tx: BlockTx[];
}

interface UndoRecord {
  treeSizeBefore: number;
  nfs: bigint[];
  accepted: number;
  rejected: number;
}

export interface ReplayOptions {
  genesis: Genesis;
  /** Exact genesis.json bytes (part of the profile hash). */
  genesisBytes: Uint8Array;
  vkey: VerificationKey;
  /** Exact vkey.json bytes (part of the profile hash). */
  vkeyBytes: Uint8Array;
}

export interface Digest {
  hex: string;
  height: number;
  tipHash: string;
  treeSize: number;
  root: string;
  nfHash: string;
  rootsHash: string;
  histHash: string;
  profile: string;
}

/** Thrown by applyBlock when the block does not extend the current tip. */
export class ChainMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ChainMismatchError';
  }
}

/** Reads genesis.json and (by default) the production vkey from disk. */
export function replayOptionsFromFiles(genesisPath: string, vkeyPath: string = CIRCUITS.main.vkey): ReplayOptions {
  const genesisBytes = new Uint8Array(readFileSync(genesisPath));
  const vkeyBytes = new Uint8Array(readFileSync(vkeyPath));
  return {
    genesis: loadGenesis(new TextDecoder().decode(genesisBytes)),
    genesisBytes,
    vkey: JSON.parse(new TextDecoder().decode(vkeyBytes)) as VerificationKey,
    vkeyBytes,
  };
}

/** Block `height` of the node's active chain, or null if that chain shrank or switched under us. */
async function fetchActiveBlock(rpc: BitcoinRpc, height: number): Promise<BlockLike | null> {
  try {
    return await rpc.getBlock(await rpc.getBlockHash(height), 2);
  } catch (e) {
    // Height out of range or block not found. Anything else (e.g. pruned data) is fatal.
    if (e instanceof RpcError && (e.code === RPC_INVALID_PARAMETER || e.code === RPC_INVALID_ADDRESS_OR_KEY)) {
      return null;
    }
    throw e;
  }
}

function u32le(x: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, x, true);
  return b;
}

const ZERO32 = new Uint8Array(32);
const STATE_DOMAIN = new TextEncoder().encode('zbtc/v1/state');

export class Replay {
  readonly genesis: Genesis;
  /** S - 1: the genesis height; replay never rolls back below it. */
  readonly baseHeight: number;
  private readonly opts: ReplayOptions;
  private readonly tree = new NoteTree();
  private readonly nullifiers = new Set<bigint>();
  private readonly roots = new Map<number, bigint>();
  private readonly hashes = new Map<number, string>();
  private readonly sizes = new Map<number, number>();
  private readonly undo = new Map<number, UndoRecord>();
  private readonly acceptedList: AcceptedEntry[] = [];
  private readonly rejectedList: RejectedEntry[] = [];
  private tipHeight: number;
  /** Number of Groth16 verifications performed (observability / tests). */
  verifyCalls = 0;
  /** Serializes sync() calls; a concurrent sync would apply blocks twice. */
  private syncChain: Promise<unknown> = Promise.resolve();
  private applying = false;

  constructor(opts: ReplayOptions) {
    this.opts = opts;
    this.genesis = opts.genesis;
    this.baseHeight = opts.genesis.startHeight - 1;
    for (const n of opts.genesis.notes) this.tree.append(n.cm);
    // R[S-1] is fixed by the inventory alone: it does not depend on any block,
    // so no block hash is recorded for S-1 and rollback stops there.
    this.roots.set(this.baseHeight, this.tree.root());
    this.sizes.set(this.baseHeight, this.tree.size);
    this.tipHeight = this.baseHeight;
  }

  /** Replays from S to the node's tip. */
  static async fresh(rpc: BitcoinRpc, opts: ReplayOptions): Promise<Replay> {
    const r = new Replay(opts);
    await r.sync(rpc);
    return r;
  }

  // ---- Queries ----

  get tip(): number {
    return this.tipHeight;
  }
  get tipHash(): string | null {
    return this.hashes.get(this.tipHeight) ?? null;
  }
  get treeSize(): number {
    return this.tree.size;
  }
  get acceptedCount(): number {
    return this.acceptedList.length;
  }
  get accepted(): readonly AcceptedEntry[] {
    return this.acceptedList;
  }
  get rejected(): readonly RejectedEntry[] {
    return this.rejectedList;
  }
  blockHashAt(h: number): string | undefined {
    return this.hashes.get(h);
  }
  /** R[h], defined for S-1 <= h <= tip. */
  rootAt(h: number): bigint | undefined {
    return this.roots.get(h);
  }
  /** |T| after block h, defined for S-1 <= h <= tip. */
  treeSizeAt(h: number): number | undefined {
    return this.sizes.get(h);
  }
  isSpent(nf: bigint): boolean {
    return this.nullifiers.has(nf);
  }
  /** Merkle path of `pos` in the tree as of block `anchorHeight` (never the current size). */
  witness(pos: number, anchorHeight: number): bigint[] {
    const size = this.sizes.get(anchorHeight);
    if (size === undefined) throw new RangeError(`no tree state at height ${anchorHeight}`);
    return this.tree.witness(pos, size);
  }
  /** Genesis notes with their positions (plaintext inventory). */
  genesisOutputs(): { pos: number; v: bigint; owner: bigint; rseed: bigint; cm: bigint }[] {
    return this.genesis.notes.map((n, pos) => ({ pos, ...n }));
  }
  /** Every accepted transfer output, in tree order. */
  outputs(): ScannableOutput[] {
    return this.acceptedList.flatMap((e) =>
      e.outputs.map((o, index) => ({ ...o, height: e.height, txid: e.txid, index })),
    );
  }

  // ---- Validation (steps 0-5) ----

  /**
   * Validates one envelope as the next transaction of block H = tip + 1,
   * against the current state, in the plan's order:
   *   0 extract (E_MULTI / E_PARSE)  1 parse (E_PARSE)  2 h_body
   *   3 max(S-1, H-W) <= h_anchor <= H-1 (E_ANCHOR)
   *   4 nf0 != nf1 (E_NF_DUP), nf not in N (E_NF_SPENT), room for 2 leaves (E_TREE_FULL)
   *   5 Groth16 verify on [R[h_anchor], h_body, nf0, nf1, cm0, cm1] (E_PROOF)
   * Steps 0-4 are cheap and run before the proof check, so a replayed or
   * self-conflicting envelope never costs a pairing.
   */
  async validate(input: Uint8Array | Extracted, H: number): Promise<Validation> {
    // 0. extract
    if (!(input instanceof Uint8Array)) {
      if (input.kind === 'none') return { ok: false, code: 'NONE', reason: 'no envelope' };
      if (input.kind === 'reject') return reject(input.code, `carrier rejected (${input.code})`);
    }
    const bytes = input instanceof Uint8Array ? input : input.bytes;
    // 1. canonical parse
    const parsed = parse(bytes);
    if (!parsed.ok) return reject('E_PARSE', parsed.reason);
    const env = parsed.env;
    // 2. h_body
    const bodyHash = hBody(bytes.subarray(0, BODY_BYTES));
    // 3. anchor window
    const anchor = this.anchorRoot(env.hAnchor, H);
    if (!anchor.ok) return anchor;
    // 4. nullifiers, tree capacity
    const conflict = this.stateConflict(env);
    if (conflict) return conflict;
    // 5. proof
    const isValidProof = await this.verifyProof(env, anchor.root, bodyHash);
    if (!isValidProof) return reject('E_PROOF', 'groth16 verification failed');
    return { ok: true, env, hBody: bodyHash };
  }

  /** Step 3. R[H] does not exist yet, so an anchor at H is impossible. */
  private anchorRoot(hAnchor: number, H: number): { ok: true; root: bigint } | Rejection {
    const lo = Math.max(this.baseHeight, H - W);
    const hi = H - 1;
    if (hAnchor < lo || hAnchor > hi) return reject('E_ANCHOR', `h_anchor ${hAnchor} not in [${lo}, ${hi}]`);
    const root = this.roots.get(hAnchor);
    if (root === undefined) return reject('E_ANCHOR', `no root at ${hAnchor}`);
    return { ok: true, root };
  }

  /**
   * Step 4. The only duplicate rule is by nullifier, never by txid or proof
   * bytes (Groth16 proofs are malleable).
   */
  private stateConflict(env: Envelope): Rejection | null {
    if (env.nf[0] === env.nf[1]) return reject('E_NF_DUP', 'nf0 == nf1');
    if (this.nullifiers.has(env.nf[0]) || this.nullifiers.has(env.nf[1])) {
      return reject('E_NF_SPENT', 'nullifier already spent');
    }
    if (this.tree.size + env.cm.length > MAX_LEAVES) return reject('E_TREE_FULL', 'note tree is full');
    return null;
  }

  /** Step 5. */
  private verifyProof(env: Envelope, anchorRoot: bigint, bodyHash: bigint): Promise<boolean> {
    this.verifyCalls++;
    const signals = publicSignalsOf(anchorRoot, bodyHash, env.nf, env.cm);
    return verifyWithVkey(this.opts.vkey, signals, bytesToProof(env.proofBytes));
  }

  // ---- Block application ----

  /**
   * Applies block H = tip + 1. Every transaction is processed in block order,
   * the coinbase included (a free publication path for miners; harmless to
   * soundness). R[H], blockhash[H] and treeSize[H] are stored only after the
   * last transaction, so nothing in block H can anchor to it.
   * Throws ChainMismatchError if the block does not extend the tip.
   */
  async applyBlock(H: number, block: BlockLike): Promise<void> {
    // tipHeight only advances after the awaits below, so a concurrent call
    // would pass the height check and apply the same block twice.
    if (this.applying) throw new Error('applyBlock is not reentrant');
    this.assertExtendsTip(H, block);

    const rec: UndoRecord = { treeSizeBefore: this.tree.size, nfs: [], accepted: 0, rejected: 0 };
    this.applying = true;
    try {
      for (let txIndex = 0; txIndex < block.tx.length; txIndex++) {
        await this.applyTransaction(H, txIndex, block.tx[txIndex], rec);
      }
    } catch (e) {
      this.undoRecord(rec);
      throw e;
    } finally {
      this.applying = false;
    }
    this.commitBlock(H, block.hash, rec);
  }

  private assertExtendsTip(H: number, block: BlockLike): void {
    if (H !== this.tipHeight + 1) throw new Error(`applyBlock(${H}) but tip is ${this.tipHeight}`);
    if (block.height !== undefined && block.height !== H) {
      throw new ChainMismatchError(`block height ${block.height} != ${H}`);
    }
    // The block at S may sit on any parent: R[S-1] is chain-independent.
    if (H > this.genesis.startHeight && block.previousblockhash !== this.hashes.get(H - 1)) {
      throw new ChainMismatchError(`block ${H} does not extend ${this.hashes.get(H - 1)}`);
    }
  }

  /** Validates transaction `txIndex` of block H and records its effect in the state and in `rec`. */
  private async applyTransaction(H: number, txIndex: number, tx: BlockTx, rec: UndoRecord): Promise<void> {
    const extracted = extractEnvelope(tx);
    if (extracted.kind === 'none') return;
    const res = await this.validate(extracted, H);
    if (res.ok) {
      this.accept(H, txIndex, tx.txid, res, rec);
    } else if (res.code !== 'NONE') {
      this.rejectedList.push({ height: H, txIndex, txid: tx.txid, code: res.code, reason: res.reason });
      rec.rejected++;
    }
  }

  /** The mutation of an accepted envelope: its nullifiers join N, its commitments join T. */
  private accept(H: number, txIndex: number, txid: string, valid: ValidEnvelope, rec: UndoRecord): void {
    const { env } = valid;
    for (const n of env.nf) {
      this.nullifiers.add(n);
      rec.nfs.push(n);
    }
    const outputs = env.cm.map((c, k) => ({
      pos: this.tree.append(c),
      cm: c,
      epk: env.epk[k],
      ct: env.ct[k],
    })) as [AcceptedOutput, AcceptedOutput];
    this.acceptedList.push({
      height: H,
      txIndex,
      txid,
      hAnchor: env.hAnchor,
      hBody: valid.hBody,
      nfs: [env.nf[0], env.nf[1]],
      outputs,
    });
    rec.accepted++;
  }

  /** After the last transaction. An empty (or all-rejected) block carries the root forward. */
  private commitBlock(H: number, hash: string, rec: UndoRecord): void {
    this.roots.set(H, rec.accepted > 0 ? this.tree.root() : (this.roots.get(H - 1) as bigint));
    this.hashes.set(H, hash);
    this.sizes.set(H, this.tree.size);
    this.undo.set(H, rec);
    this.tipHeight = H;
  }

  private undoRecord(rec: UndoRecord): void {
    this.tree.truncate(rec.treeSizeBefore);
    for (const n of rec.nfs) this.nullifiers.delete(n);
    this.acceptedList.length -= rec.accepted;
    this.rejectedList.length -= rec.rejected;
  }

  /** Pops the tip block. Never goes below S-1. */
  rollback(): void {
    const H = this.tipHeight;
    if (H <= this.baseHeight) throw new Error('cannot roll back below the genesis height S-1');
    const rec = this.undo.get(H);
    if (!rec) throw new Error(`no undo record for ${H}`);
    this.undoRecord(rec);
    this.roots.delete(H);
    this.hashes.delete(H);
    this.sizes.delete(H);
    this.undo.delete(H);
    this.tipHeight = H - 1;
  }

  /**
   * Follows the node's active chain: rolls back while the tip is above the
   * node's height or its hash differs from the node's (never below S-1), then
   * applies blocks up to the node's tip. Loops until stable. Concurrent calls
   * are queued and run one after another.
   */
  sync(rpc: BitcoinRpc): Promise<{ rolledBack: number; applied: number }> {
    const run = this.syncChain.then(() => this.syncOnce(rpc));
    this.syncChain = run.catch(() => undefined);
    return run;
  }

  private async syncOnce(rpc: BitcoinRpc): Promise<{ rolledBack: number; applied: number }> {
    let rolledBack = 0;
    let applied = 0;
    for (;;) {
      const nodeHeight = await rpc.getBlockCount();
      rolledBack += await this.rollbackToNodeChain(rpc, nodeHeight);
      const forward = await this.applyNodeBlocks(rpc, nodeHeight);
      applied += forward.applied;
      if (!forward.isChainMismatch && (await this.isSyncedWith(rpc))) break;
    }
    return { rolledBack, applied };
  }

  /** Rolls back (never below S-1) while the tip is above nodeHeight or its hash differs from the node's. */
  private async rollbackToNodeChain(rpc: BitcoinRpc, nodeHeight: number): Promise<number> {
    let rolledBack = 0;
    while (this.tipHeight > this.baseHeight) {
      const mine = this.hashes.get(this.tipHeight);
      if (this.tipHeight <= nodeHeight && mine === (await rpc.getBlockHash(this.tipHeight))) break;
      this.rollback();
      rolledBack++;
    }
    return rolledBack;
  }

  /** Applies the node's blocks up to nodeHeight; stops early if its chain shrank or switched meanwhile. */
  private async applyNodeBlocks(
    rpc: BitcoinRpc,
    nodeHeight: number,
  ): Promise<{ applied: number; isChainMismatch: boolean }> {
    let applied = 0;
    for (let h = this.tipHeight + 1; h <= nodeHeight; h++) {
      const block = await fetchActiveBlock(rpc, h);
      if (!block) return { applied, isChainMismatch: true };
      try {
        await this.applyBlock(h, block);
      } catch (e) {
        if (e instanceof ChainMismatchError) return { applied, isChainMismatch: true };
        throw e;
      }
      applied++;
    }
    return { applied, isChainMismatch: false };
  }

  /** True when the node's tip is ours (or still at or below S-1), i.e. it did not move during the sync. */
  private async isSyncedWith(rpc: BitcoinRpc): Promise<boolean> {
    const best = await rpc.getBestBlockHash();
    const nodeHeight = await rpc.getBlockCount();
    return nodeHeight <= this.baseHeight || (nodeHeight === this.tipHeight && best === this.tipHash);
  }

  // ---- Digest ----

  /** Profile: SHA256(vkeyBytes || genesisBytes || u32le(W) || u32le(K_MIN) || u8(DEPTH)). */
  profile(): Uint8Array {
    return sha256
      .create()
      .update(this.opts.vkeyBytes)
      .update(this.opts.genesisBytes)
      .update(u32le(W))
      .update(u32le(K_MIN))
      .update(new Uint8Array([DEPTH]))
      .digest();
  }

  /**
   * digest = SHA256("zbtc/v1/state" || u32le(H) || tipHash || u32le(|T|) || root
   *                 || nfHash || rootsHash || histHash || profile)
   *   nfHash    = SHA256(sorted nullifiers, 32 B BE each)
   *   rootsHash = SHA256(for h = S-1..H: u32le(h) || R[h])
   *   histHash  = SHA256(for each accepted entry in order:
   *                      u32le(height) || u32le(txIndex) || txid bytes || hBody (32 B))
   * tipHash is the display-hex block hash as bytes, or 32 zero bytes at S-1.
   */
  digest(): Digest {
    const H = this.tipHeight;
    const tipHash = this.tipHash ? hexToBytes(this.tipHash) : ZERO32;
    const root = bigIntToBytes(this.roots.get(H) as bigint);

    const nfHasher = sha256.create();
    for (const n of [...this.nullifiers].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
      nfHasher.update(bigIntToBytes(n));
    }
    const nfHash = nfHasher.digest();

    const rootsHasher = sha256.create();
    for (let h = this.baseHeight; h <= H; h++) {
      rootsHasher.update(u32le(h)).update(bigIntToBytes(this.roots.get(h) as bigint));
    }
    const rootsHash = rootsHasher.digest();

    const histHasher = sha256.create();
    for (const e of this.acceptedList) {
      histHasher
        .update(u32le(e.height))
        .update(u32le(e.txIndex))
        .update(hexToBytes(e.txid))
        .update(bigIntToBytes(e.hBody));
    }
    const histHash = histHasher.digest();
    const profile = this.profile();

    const d = sha256
      .create()
      .update(STATE_DOMAIN)
      .update(u32le(H))
      .update(tipHash)
      .update(u32le(this.tree.size))
      .update(root)
      .update(nfHash)
      .update(rootsHash)
      .update(histHash)
      .update(profile)
      .digest();

    return {
      hex: bytesToHex(d),
      height: H,
      tipHash: bytesToHex(tipHash),
      treeSize: this.tree.size,
      root: bytesToHex(root),
      nfHash: bytesToHex(nfHash),
      rootsHash: bytesToHex(rootsHash),
      histHash: bytesToHex(histHash),
      profile: bytesToHex(profile),
    };
  }
}
