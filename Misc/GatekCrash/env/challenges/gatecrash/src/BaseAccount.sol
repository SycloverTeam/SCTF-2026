// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IAccount.sol";
import "./IEntryPoint.sol";

contract BaseAccount is IAccount {

    address public owner;
    uint48 public validationModuleFlag;
    address public validationModule;

    IEntryPoint public immutable entryPoint;
    uint256 public nonce;

    modifier onlyOwner() {
        require(msg.sender == owner, "BaseAccount: only owner");
        _;
    }

    constructor(address _entryPoint, address _owner) {
        require(_owner != address(0), "BaseAccount: zero owner");
        entryPoint = IEntryPoint(_entryPoint);
        owner = _owner;
        validationModuleFlag = 0;
        validationModule = address(0);
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        require(
            msg.sender == address(entryPoint),
            "BaseAccount: only EntryPoint"
        );

        require(
            entryPoint.currentOpSender() == address(this),
            "BaseAccount: sender mismatch"
        );

        if (validationModule != address(0)) {
            _delegateToModule(userOp, userOpHash);
        }

        if (entryPoint.preApprovedSenders(address(this))) {
            require(userOp.nonce == nonce, "BaseAccount: invalid nonce");
            nonce++;
            return 0;
        }

        _validateSignature(userOp, userOpHash);

        require(userOp.nonce == nonce, "BaseAccount: invalid nonce");
        nonce++;

        return 0;
    }

    function _delegateToModule(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal {
        bytes memory data = abi.encodeWithSignature(
            "preValidate(address,bytes32)",
            userOp.sender,
            userOpHash
        );
        (bool modSuccess, ) = validationModule.delegatecall(data);
        if (!modSuccess) {
            validationModuleFlag = 0;
        } else {
            unchecked {
                validationModuleFlag += 1;
            }
        }
    }

    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)
        );

        address recovered = _recoverSigner(digest, userOp.signature);

        require(
            recovered == owner,
            "BaseAccount: invalid signature"
        );
    }

    function _recoverSigner(
        bytes32 digest,
        bytes memory signature
    ) internal pure returns (address) {
        require(signature.length == 65, "BaseAccount: invalid sig length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        require(v != 0 && v != 1, "BaseAccount: invalid v");

        if (v < 27) {
            v += 27;
        }
        require(v == 27 || v == 28, "BaseAccount: invalid v");

        return ecrecover(digest, v, r, s);
    }

    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external {
        require(
            msg.sender == address(entryPoint),
            "BaseAccount: only EntryPoint"
        );
        (bool success, ) = dest.call{value: value}(func);
        require(success, "BaseAccount: execution failed");
    }

    function updateValidationModule(address newModule) external {
        require(
            msg.sender == address(entryPoint),
            "BaseAccount: only EntryPoint"
        );
        validationModule = newModule;
        validationModuleFlag = 0;
    }

    function addDeposit() external payable onlyOwner {
        (bool success, ) = address(entryPoint).call{value: msg.value}("");
        require(success, "BaseAccount: deposit failed");
    }

    receive() external payable {}
}