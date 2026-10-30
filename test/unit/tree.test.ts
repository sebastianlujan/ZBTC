import { describe, expect, it } from 'vitest';
import { DEPTH } from '../../src/constants.js';
import { hashPair, randomField } from '../../src/crypto.js';
import { EMPTY_ROOT, NoteTree, ZEROS } from '../../src/tree.js';

function filledTree(n: number): NoteTree {
  const t = new NoteTree();
  for (let i = 0; i < n; i++) t.append(randomField());
  return t;
}

describe('NoteTree', () => {
  it('empty root is a fixed constant', () => {
    // Recompute independently of the module's ZEROS table.
    let z = 0n;
    for (let d = 0; d < DEPTH; d++) z = hashPair(z, z);
    expect(new NoteTree().root()).toBe(z);
    expect(EMPTY_ROOT).toBe(z);
    expect(new NoteTree().root()).toBe(new NoteTree().root());
    expect(ZEROS).toHaveLength(DEPTH + 1);
  });

  it('append returns sequential positions and size tracks them', () => {
    const t = new NoteTree();
    expect(t.size).toBe(0);
    expect(t.append(randomField())).toBe(0);
    expect(t.append(randomField())).toBe(1);
    expect(t.append(randomField())).toBe(2);
    expect(t.size).toBe(3);
  });

  it('verifyPath(leaf, pos, witness) matches root() for every leaf', () => {
    for (const n of [1, 2, 3, 5, 8, 13]) {
      const t = filledTree(n);
      for (let pos = 0; pos < n; pos++) {
        expect(NoteTree.verifyPath(t.leaf(pos), pos, t.witness(pos))).toBe(t.root());
      }
    }
  });

  it('a witness for an old prefix verifies against the old root', () => {
    const t = filledTree(5);
    const oldSize = t.size;
    const oldRoot = t.root();
    const oldPaths = Array.from({ length: oldSize }, (_, pos) => t.witness(pos));
    for (let i = 0; i < 6; i++) t.append(randomField());

    expect(t.root()).not.toBe(oldRoot);
    expect(t.rootAt(oldSize)).toBe(oldRoot);
    for (let pos = 0; pos < oldSize; pos++) {
      const w = t.witness(pos, oldSize);
      expect(w).toEqual(oldPaths[pos]);
      expect(NoteTree.verifyPath(t.leaf(pos), pos, w)).toBe(oldRoot);
      // The same leaf against the new size yields the new root, not the old one.
      expect(NoteTree.verifyPath(t.leaf(pos), pos, t.witness(pos))).toBe(t.root());
    }
  });

  it('truncate restores the previous root', () => {
    const t = filledTree(4);
    const roots = [t.rootAt(0), t.rootAt(1), t.rootAt(2), t.rootAt(3), t.root()];
    t.append(randomField());
    t.append(randomField());
    t.truncate(4);
    expect(t.size).toBe(4);
    expect(t.root()).toBe(roots[4]);
    t.truncate(1);
    expect(t.root()).toBe(roots[1]);
    t.truncate(0);
    expect(t.root()).toBe(EMPTY_ROOT);
  });

  it('a path does not verify at a different position or with a different leaf', () => {
    const t = filledTree(4);
    const w = t.witness(2);
    expect(NoteTree.verifyPath(t.leaf(2), 3, w)).not.toBe(t.root());
    expect(NoteTree.verifyPath(t.leaf(1), 2, w)).not.toBe(t.root());
  });

  it('rejects out-of-range sizes and positions', () => {
    const t = filledTree(3);
    expect(() => t.rootAt(4)).toThrow(RangeError);
    expect(() => t.witness(3)).toThrow(RangeError);
    expect(() => t.witness(2, 2)).toThrow(RangeError);
    expect(() => t.truncate(4)).toThrow(RangeError);
    expect(() => NoteTree.verifyPath(0n, 2 ** DEPTH, new Array<bigint>(DEPTH).fill(0n))).toThrow(RangeError);
    expect(() => NoteTree.verifyPath(0n, 0, [])).toThrow(RangeError);
  });
});
