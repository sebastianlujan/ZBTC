pragma circom 2.1.9;

// TEST-ONLY, UNSAFE VARIANT. Never deploy or accept proofs from this circuit.
//
// Same statement as circuits/transfer.circom but WITHOUT the 64-bit range
// checks on values (RANGE = 0). A prover can then create an output of value
// r - x that wraps around the field and balances any sum: unlimited inflation.
// It exists only so test C3 can show that the range checks are what prevent it.

include "../transfer_template.circom";

component main {public [root, hBody, nf, cm]} = Transfer(2, 2, 20, 0, 1);
