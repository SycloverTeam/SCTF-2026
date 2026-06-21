// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Groth16Verifier} from "./Groth16Verifier.sol";

contract LastHonestWitness {
    error InvalidFactor();
    error InvalidPlaintext();
    error InvalidCommitment();
    error InvalidMerklePath();
    error InvalidProof();
    error NullifierAlreadyUsed();
    error TransferFailed();
    error IncorrectRewardValue();
    error InvalidPageA();
    error InvalidPageB();
    error InvalidPageC();

    uint256 public constant REWARD = 100 ether;
    uint256 public constant VAULT_A_REWARD = 34 ether;
    uint256 public constant VAULT_B_REWARD = 33 ether;
    uint256 public constant VAULT_C_REWARD = 33 ether;
    uint256 public constant TREE_LEVELS = 5;
    uint256 public constant LEAF_COUNT = 32;
    uint256 public constant FACTOR_BOUND = 1 << 60;

    uint256 public constant EXTERNAL_NULLIFIER = 48_879;
    uint256 public constant RECIPIENT_COMMITMENT =
        9377985761090098792458769157668700179213141594497154267610801610404565099971;
    uint256 public constant PAGE_A_N = 760009694642386684565581461392043895505912502559714131532944907541093903;
    uint256 public constant PAGE_A_E = 3;
    uint256 public constant PAGE_A_DELTA = 1_337;
    uint256 public constant PAGE_A_C1 = 453597385863057272648915757216738828698620960961179478921819470254014847;
    uint256 public constant PAGE_A_C2 = 453597385865721903738147200739079200525533155295038017694987515419712854;
    uint256 public constant PAGE_B_PUB_X = 58815339488302044413775644787852249409224615099495920880759980194063649848583;
    uint256 public constant PAGE_B_PUB_Y = 98550888334717328604002147137887649681647570376424892468560957640988111280493;
    address public constant PAGE_B_SIGNER = 0xB6746A0bfDC4aF89cE8cE8822c887A6bB79b88ec;
    bytes32 public constant PAGE_B_MESSAGE_HASH = 0x99e1c9445f2a4aaed1cb39c5f061cff3410bf6faa5828abcafe330974301c838;
    uint256 public constant PAGE_C_INPUT_BOUND = 1 << 32;
    uint256 public constant PAGE_C_MASK = (1 << 40) - 1;

    bytes32 internal constant PAGE_C_TAG = keccak256("LAST_HONEST_WITNESS_PAGE_C");

    uint256 private modulus;
    uint256 private publicExponent;
    uint256 private ciphertext;
    uint256 private merkleRoot;
    Groth16Verifier private immutable VERIFIER;
    FragmentVault private vaultA;
    FragmentVault private vaultB;
    FragmentVault private vaultC;

    mapping(uint256 => bool) public usedNullifiers;

    constructor(
        uint256 modulus_,
        uint256 publicExponent_,
        uint256 ciphertext_,
        uint256 merkleRoot_,
        Groth16Verifier verifier_
    ) payable {
        if (msg.value != REWARD) {
            revert IncorrectRewardValue();
        }
        modulus = modulus_;
        publicExponent = publicExponent_;
        ciphertext = ciphertext_;
        merkleRoot = merkleRoot_;
        VERIFIER = verifier_;
        vaultA = new FragmentVault{value: VAULT_A_REWARD}();
        vaultB = new FragmentVault{value: VAULT_B_REWARD}();
        vaultC = new FragmentVault{value: VAULT_C_REWARD}();
    }

    function claim(
        uint[2] calldata proofA,
        uint[2][2] calldata proofB,
        uint[2] calldata proofC,
        uint[5] calldata publicSignals,
        uint256 pageAPlaintext,
        uint8 pageBv,
        bytes32 pageBr,
        bytes32 pageBs,
        uint256 pageCLeft,
        uint256 pageCRight
    ) external {
        if (
            publicSignals[0] != modulus || publicSignals[1] != merkleRoot
                || publicSignals[2] != RECIPIENT_COMMITMENT || publicSignals[4] != EXTERNAL_NULLIFIER
        ) {
            revert InvalidProof();
        }
        if (!VERIFIER.verifyProof(proofA, proofB, proofC, publicSignals)) {
            revert InvalidProof();
        }

        uint256 nullifierHash = publicSignals[3];
        if (usedNullifiers[nullifierHash]) {
            revert NullifierAlreadyUsed();
        }

        _verifyPageA(pageAPlaintext);
        _verifyPageB(pageBv, pageBr, pageBs);
        _verifyPageC(pageCLeft, pageCRight);

        usedNullifiers[nullifierHash] = true;

        vaultA.sweep(payable(msg.sender));
        vaultB.sweep(payable(msg.sender));
        vaultC.sweep(payable(msg.sender));
    }

    function vaults() external view returns (address, address, address) {
        return (address(vaultA), address(vaultB), address(vaultC));
    }

    function isSolved() external view returns (bool) {
        return address(vaultA).balance == 0 && address(vaultB).balance == 0 && address(vaultC).balance == 0;
    }

    function _verifyPageA(uint256 plaintext_) internal pure {
        if (
            plaintext_ >= PAGE_A_N || _powSmall(plaintext_, PAGE_A_E, PAGE_A_N) != PAGE_A_C1
                || _powSmall(plaintext_ + PAGE_A_DELTA, PAGE_A_E, PAGE_A_N) != PAGE_A_C2
        ) {
            revert InvalidPageA();
        }
    }

    function _verifyPageB(uint8 v, bytes32 r, bytes32 s) internal pure {
        if (v != 27 && v != 28) {
            revert InvalidPageB();
        }
        address signer = ecrecover(PAGE_B_MESSAGE_HASH, v, r, s);
        if (signer != PAGE_B_SIGNER) {
            revert InvalidPageB();
        }
    }

    function _verifyPageC(uint256 a, uint256 b) internal pure {
        if (a == b || a >= PAGE_C_INPUT_BOUND || b >= PAGE_C_INPUT_BOUND) {
            revert InvalidPageC();
        }
        if (_pageCDigest(a) != _pageCDigest(b)) {
            revert InvalidPageC();
        }
    }

    function _powSmall(uint256 base, uint256 exponent, uint256 modulus_) internal pure returns (uint256 result) {
        result = 1;
        while (exponent != 0) {
            if (exponent & 1 == 1) {
                result = mulmod(result, base, modulus_);
            }
            base = mulmod(base, base, modulus_);
            exponent >>= 1;
        }
    }

    function _pageCDigest(uint256 value) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(PAGE_C_TAG, value))) & PAGE_C_MASK;
    }
}

contract FragmentVault {
    error Unauthorized();
    error TransferFailed();

    address private immutable OWNER;

    constructor() payable {
        OWNER = msg.sender;
    }

    function sweep(address payable recipient) external {
        if (msg.sender != OWNER) {
            revert Unauthorized();
        }
        (bool sent,) = recipient.call{value: address(this).balance}("");
        if (!sent) {
            revert TransferFailed();
        }
    }
}
