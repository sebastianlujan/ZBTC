pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

// Root of a binary Poseidon(2) Merkle tree of height DEPTH.
//
// pos is range-checked to DEPTH bits (Num2Bits), so a position cannot alias
// pos + 2^DEPTH. Bit i of pos (LSB first) selects the side at level i:
//   bit = 0 -> the current node is the LEFT child:  H(cur, sib)
//   bit = 1 -> the current node is the RIGHT child: H(sib, cur)
template MerkleRoot(DEPTH) {
    signal input leaf;
    signal input pos;
    signal input path[DEPTH];
    signal output root;

    component bits = Num2Bits(DEPTH);
    bits.in <== pos;

    signal cur[DEPTH + 1];
    signal d[DEPTH];
    component h[DEPTH];

    cur[0] <== leaf;
    for (var i = 0; i < DEPTH; i++) {
        // One-constraint conditional swap:
        //   d = bit * (sib - cur); left = cur + d; right = sib - d
        d[i] <== bits.out[i] * (path[i] - cur[i]);
        h[i] = Poseidon(2);
        h[i].inputs[0] <== cur[i] + d[i];
        h[i].inputs[1] <== path[i] - d[i];
        cur[i + 1] <== h[i].out;
    }

    root <== cur[DEPTH];
}
