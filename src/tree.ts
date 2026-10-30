// Append-only Poseidon(2) Merkle tree of note commitments, height DEPTH.
//
// Empty leaves are 0. Leaf positions are assigned in append order. The tree
// keeps every leaf so it can produce roots and witnesses for any historical
// prefix (an anchor at an older height commits to a prefix of the leaves).
// Recomputing from the leaves is O(n * DEPTH), which is fine for regtest.
import { DEPTH, MAX_LEAVES } from './constants.js';
import { assertField, hashPair } from './crypto.js';

/** ZEROS[d] = root of an empty subtree of height d. ZEROS[0] = 0 (empty leaf). */
export const ZEROS: readonly bigint[] = (() => {
  const zeros: bigint[] = [0n];
  for (let d = 0; d < DEPTH; d++) zeros.push(hashPair(zeros[d], zeros[d]));
  return zeros;
})();

/** Root of the empty tree. */
export const EMPTY_ROOT = ZEROS[DEPTH];

export class NoteTree {
  private leaves: bigint[] = [];

  constructor(leaves: readonly bigint[] = []) {
    for (const leaf of leaves) this.append(leaf);
  }

  /** Number of appended leaves. */
  get size(): number {
    return this.leaves.length;
  }

  /** Appends a commitment and returns its position. */
  append(cm: bigint): number {
    assertField(cm, 'cm');
    if (this.leaves.length >= MAX_LEAVES) throw new RangeError('note tree is full');
    this.leaves.push(cm);
    return this.leaves.length - 1;
  }

  /** Leaf at pos (must be < size). */
  leaf(pos: number): bigint {
    this.checkPos(pos, this.size);
    return this.leaves[pos];
  }

  /** Current root. */
  root(): bigint {
    return this.rootAt(this.size);
  }

  /** Root of the tree made of the first `size` leaves. */
  rootAt(size: number): bigint {
    this.checkSize(size);
    let level = this.leaves.slice(0, size);
    for (let d = 0; d < DEPTH; d++) level = NoteTree.parentLevel(level, d);
    return level.length === 0 ? EMPTY_ROOT : level[0];
  }

  /**
   * Authentication path (siblings, leaf level first) of leaf `pos` in the tree
   * made of the first `size` leaves. Defaults to the current size.
   */
  witness(pos: number, size: number = this.size): bigint[] {
    this.checkSize(size);
    this.checkPos(pos, size);
    const path: bigint[] = [];
    let level = this.leaves.slice(0, size);
    let index = pos;
    for (let d = 0; d < DEPTH; d++) {
      const sibling = index ^ 1;
      path.push(sibling < level.length ? level[sibling] : ZEROS[d]);
      level = NoteTree.parentLevel(level, d);
      index >>= 1;
    }
    return path;
  }

  /** Drops every leaf at position >= size (reorg rollback). */
  truncate(size: number): void {
    this.checkSize(size);
    this.leaves.length = size;
  }

  /**
   * Root implied by a leaf, its position and its path. Bit i of pos = 0 means
   * the current node is the LEFT child at level i (same rule as the circuit).
   */
  static verifyPath(leaf: bigint, pos: number, path: readonly bigint[]): bigint {
    if (path.length !== DEPTH) throw new RangeError(`path must have ${DEPTH} elements`);
    if (!Number.isInteger(pos) || pos < 0 || pos >= MAX_LEAVES) throw new RangeError('pos out of range');
    let node = leaf;
    for (let d = 0; d < DEPTH; d++) {
      const isLeftChild = ((pos >> d) & 1) === 0;
      node = isLeftChild ? hashPair(node, path[d]) : hashPair(path[d], node);
    }
    return node;
  }

  private static parentLevel(level: readonly bigint[], d: number): bigint[] {
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(hashPair(level[i], i + 1 < level.length ? level[i + 1] : ZEROS[d]));
    }
    return next;
  }

  private checkSize(size: number): void {
    if (!Number.isInteger(size) || size < 0 || size > this.leaves.length) {
      throw new RangeError(`size ${size} out of range [0, ${this.leaves.length}]`);
    }
  }

  private checkPos(pos: number, size: number): void {
    if (!Number.isInteger(pos) || pos < 0 || pos >= size) {
      throw new RangeError(`pos ${pos} out of range [0, ${size})`);
    }
  }
}
