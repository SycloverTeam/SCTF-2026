// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LastHonestWitness} from "./Challenge.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

contract Setup {
    LastHonestWitness public challenge;

    uint256 private rsaModulus;
    uint256 private rsaExponent;
    uint256 private rsaCiphertext;

    bytes32 private constant PARAMETER_TAG = keccak256("LAST_HONEST_WITNESS_SETUP_PARAMETERS");

    event WitnessRoot(bytes32 indexed merkleRoot);

    constructor() payable {
        require(msg.value == 100 ether, "Setup requires 100 ETH");

        uint256 n = _derive("N", 0x97dff7b071618773b336fb4b412bdf027c604766d118f39adc8643d691a08589);
        uint256 e = _derive("E", 0xcad2da8eef0f36ba8a88ccb5d0b95a29627251c264bc55b62b0adadd5c948004);
        uint256 c = _derive("C", 0x9536e89476927745cc5c8cdfd36e38a3f93f9bff2d80880ade5ba55ba199bee3);
        uint256 root = _derive("ROOT", 0x30d48ce879bb3173fe7f2dec84d889069d0f60a8c89f1da1c08f3d4afacd1bf9);

        rsaModulus = n;
        rsaExponent = e;
        rsaCiphertext = c;

        emit WitnessRoot(bytes32(root));
        Groth16Verifier verifier = new Groth16Verifier();
        challenge = new LastHonestWitness{value: 100 ether}(n, e, c, root, verifier);
    }

    function isSolved() external view returns (bool) {
        return challenge.isSolved();
    }

    function _derive(string memory label, uint256 mask) private pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(PARAMETER_TAG, label))) ^ mask;
    }
}
