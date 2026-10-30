pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "./merkle.circom";

// ZBTC shielded transfer statement (N_IN inputs, N_OUT outputs).
//
// This file holds only the template. circom rejects a project with more than
// one `component main`, so every main (transfer.circom and the test-only
// variants) lives in its own file and includes this one.
//
// Template parameters:
//   DEPTH  Merkle tree height (positions are DEPTH-bit integers).
//   RANGE  1 = range-check every value to 64 bits. 0 is UNSAFE (inflation).
//   BIND   1 = add the hBody^2 insurance constraint. 0 is test-only.
//
// Public inputs (declaration order fixes the public signal order):
//   root, hBody, nf[N_IN], cm[N_OUT]
template Transfer(N_IN, N_OUT, DEPTH, RANGE, BIND) {
    // Domain tags; must match src/constants.ts.
    var DOM_OWN = 1;
    var DOM_NFK = 2;
    var DOM_CM = 3;
    var DOM_NF = 4;
    var VALUE_BITS = 64;

    // ---- Public inputs (keep this order) ----
    signal input root;
    signal input hBody;
    signal input nf[N_IN];
    signal input cm[N_OUT];

    // ---- Private inputs ----
    signal input skSpend;
    signal input inV[N_IN];
    signal input inRseed[N_IN];
    signal input inPos[N_IN];
    signal input inPath[N_IN][DEPTH];
    signal input outV[N_OUT];
    signal input outOwner[N_OUT];
    signal input outRseed[N_OUT];

    // ---- Spending key -> owner and nullifier key ----
    component ownerH = Poseidon(2);
    ownerH.inputs[0] <== DOM_OWN;
    ownerH.inputs[1] <== skSpend;
    signal owner <== ownerH.out;

    component skNfH = Poseidon(2);
    skNfH.inputs[0] <== DOM_NFK;
    skNfH.inputs[1] <== skSpend;
    signal skNf <== skNfH.out;

    // ---- Inputs: commitment, membership, nullifier ----
    component inCmH[N_IN];
    component inTree[N_IN];
    component nfH[N_IN];
    var sumIn = 0;
    for (var i = 0; i < N_IN; i++) {
        inCmH[i] = Poseidon(4);
        inCmH[i].inputs[0] <== DOM_CM;
        inCmH[i].inputs[1] <== inV[i];
        inCmH[i].inputs[2] <== owner;
        inCmH[i].inputs[3] <== inRseed[i];

        inTree[i] = MerkleRoot(DEPTH);
        inTree[i].leaf <== inCmH[i].out;
        inTree[i].pos <== inPos[i];
        for (var j = 0; j < DEPTH; j++) {
            inTree[i].path[j] <== inPath[i][j];
        }
        // Membership is enforced only for non-zero values: a zero-value dummy
        // input may use any path.
        (inTree[i].root - root) * inV[i] === 0;

        nfH[i] = Poseidon(4);
        nfH[i].inputs[0] <== DOM_NF;
        nfH[i].inputs[1] <== skNf;
        nfH[i].inputs[2] <== inRseed[i];
        nfH[i].inputs[3] <== inPos[i];
        nf[i] === nfH[i].out;

        sumIn += inV[i];
    }

    // ---- Outputs: commitment ----
    component outCmH[N_OUT];
    var sumOut = 0;
    for (var k = 0; k < N_OUT; k++) {
        outCmH[k] = Poseidon(4);
        outCmH[k].inputs[0] <== DOM_CM;
        outCmH[k].inputs[1] <== outV[k];
        outCmH[k].inputs[2] <== outOwner[k];
        outCmH[k].inputs[3] <== outRseed[k];
        cm[k] === outCmH[k].out;

        sumOut += outV[k];
    }

    // ---- 64-bit range checks on every value (gated by RANGE) ----
    // Num2Bits(64) constrains v = sum(b_i * 2^i) with boolean b_i, so v < 2^64.
    // The bits themselves are not needed, hence the discarded outputs.
    if (RANGE == 1) {
        for (var i = 0; i < N_IN; i++) {
            _ <== Num2Bits(VALUE_BITS)(inV[i]);
        }
        for (var k = 0; k < N_OUT; k++) {
            _ <== Num2Bits(VALUE_BITS)(outV[k]);
        }
    }

    // ---- Value conservation ----
    // With RANGE == 1 each side is < N * 2^64, far below the field modulus,
    // so the equality cannot hold by wrap-around.
    sumIn === sumOut;

    // ---- Nullifiers within one transfer are pairwise distinct ----
    if (N_IN > 1) {
        component nfEq[N_IN * (N_IN - 1) / 2];
        var e = 0;
        for (var a = 0; a < N_IN; a++) {
            for (var b = a + 1; b < N_IN; b++) {
                nfEq[e] = IsZero();
                nfEq[e].in <== nf[a] - nf[b];
                nfEq[e].out === 0;
                e++;
            }
        }
    }

    // ---- Insurance: make hBody appear in a constraint ----
    if (BIND == 1) {
        signal hSq <== hBody * hBody;
    }
}
