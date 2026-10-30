pragma circom 2.1.9;

// Production statement: Transfer(2, 2, 20) with range checks and hBody binding.
// Public signal order: [root, hBody, nf[0], nf[1], cm[0], cm[1]].

include "./transfer_template.circom";

component main {public [root, hBody, nf, cm]} = Transfer(2, 2, 20, 1, 1);
