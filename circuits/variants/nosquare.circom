pragma circom 2.1.9;

// TEST-ONLY, UNSAFE VARIANT. Never deploy or accept proofs from this circuit.
//
// Same statement as circuits/transfer.circom but WITHOUT the hBody^2 insurance
// constraint (BIND = 0), so hBody appears in no constraint at all. Test C9b
// uses it to show that the snarkjs verifier still binds hBody through its IC
// term, i.e. the square is insurance, not the only binding.

include "../transfer_template.circom";

component main {public [root, hBody, nf, cm]} = Transfer(2, 2, 20, 1, 0);
