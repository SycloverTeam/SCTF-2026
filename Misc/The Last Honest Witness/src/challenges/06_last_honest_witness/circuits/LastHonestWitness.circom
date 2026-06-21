pragma circom 2.1.6;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../../node_modules/circomlib/circuits/bitify.circom";

template LastHonestWitness(levels) {
    signal input p;
    signal input q;
    signal input plaintext;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal input modulus;
    signal input merkleRoot;
    signal input recipientCommitment;
    signal input nullifierHash;
    signal input externalNullifier;

    component pBits = Num2Bits(60);
    component qBits = Num2Bits(60);
    pBits.in <== p;
    qBits.in <== q;

    p * q === modulus;

    component plaintextLtModulus = LessThan(128);
    plaintextLtModulus.in[0] <== plaintext;
    plaintextLtModulus.in[1] <== modulus;
    plaintextLtModulus.out === 1;

    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== 1;
    commitmentHasher.inputs[1] <== plaintext;
    recipientCommitment === commitmentHasher.out;

    component identityHasher = Poseidon(5);
    identityHasher.inputs[0] <== 2;
    identityHasher.inputs[1] <== plaintext;
    identityHasher.inputs[2] <== p;
    identityHasher.inputs[3] <== q;
    identityHasher.inputs[4] <== externalNullifier;

    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== 5;
    nullifierHasher.inputs[1] <== identityHasher.out;
    nullifierHasher.inputs[2] <== externalNullifier;
    nullifierHash === nullifierHasher.out;

    component leafHasher = Poseidon(3);
    leafHasher.inputs[0] <== 3;
    leafHasher.inputs[1] <== identityHasher.out;
    leafHasher.inputs[2] <== commitmentHasher.out;

    signal current[levels + 1];
    current[0] <== leafHasher.out;

    component nodeHashers[levels];
    signal left[levels];
    signal right[levels];

    for (var i = 0; i < levels; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        left[i] <== current[i] + pathIndices[i] * (pathElements[i] - current[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (current[i] - pathElements[i]);

        nodeHashers[i] = Poseidon(3);
        nodeHashers[i].inputs[0] <== 4;
        nodeHashers[i].inputs[1] <== left[i];
        nodeHashers[i].inputs[2] <== right[i];
        current[i + 1] <== nodeHashers[i].out;
    }

    current[levels] === merkleRoot;
}

component main { public [modulus, merkleRoot, recipientCommitment, nullifierHash, externalNullifier] } =
    LastHonestWitness(5);
