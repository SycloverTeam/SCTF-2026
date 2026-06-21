// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IEntryPoint.sol";
import "./IAccount.sol";
import "./IPaymaster.sol";

contract EntryPoint is IEntryPoint {

    address public override currentOpSender;
    bytes32 public override currentOpHash;
    mapping(address => bool) public preApprovedSenders;
    mapping(bytes32 => bool) public validatedOps;
    mapping(address => uint256) public balanceOf;

    address public immutable factory;
    mapping(address => bool) public registeredSenders;

    uint256 private _validationGasAccumulator;
    uint256 private _executionPhaseFlag;
    address private _lastPaymaster;
    bool    private _inPaymasterValidation;

    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost
    );

    event PreApprovedSenderAdded(address indexed sender);
    event PreApprovedSenderRemoved(address indexed sender);
    event ModuleUpdated(address indexed account, address indexed newModule);
    event GasAccounting(uint256 phase, uint256 gasUsed, uint256 accumulator);

    constructor(address _factory) {
        require(_factory != address(0), "EP: zero factory");
        factory = _factory;
    }

    function handleOps(
        UserOperation[] calldata ops,
        address payable beneficiary
    ) external {
        uint256 opsLength = ops.length;
        _executionPhaseFlag = 1;

        for (uint256 i = 0; i < opsLength; i++) {
            _validatePrepayment(i, ops[i]);
            _cacheSenderContext(ops[i]);
        }

        _executionPhaseFlag = 2;

        for (uint256 i = 0; i < opsLength; i++) {
            _executeUserOp(i, ops[i]);
        }

        _executionPhaseFlag = 0;
        _payBeneficiary(beneficiary);
    }

    function _validatePrepayment(
        uint256 opIndex,
        UserOperation calldata op
    ) internal {
        currentOpSender = op.sender;

        require(registeredSenders[op.sender], "EP: unregistered sender");

        bytes32 opHash = keccak256(abi.encode(
            op.sender,
            op.nonce,
            keccak256(op.initCode),
            keccak256(op.callData),
            op.callGasLimit,
            op.verificationGasLimit,
            op.preVerificationGas,
            op.maxFeePerGas,
            op.maxPriorityFeePerGas,
            keccak256(op.paymasterAndData)
        ));
        currentOpHash = opHash;

        uint256 validationData = IAccount(op.sender).validateUserOp(
            op,
            opHash,
            0
        );

        _trackValidationGas(validationData);

        if (op.paymasterAndData.length > 0) {
            address paymaster = _extractPaymaster(op.paymasterAndData);
            _lastPaymaster = paymaster;
            _inPaymasterValidation = true;
            IPaymaster(paymaster).validatePaymasterUserOp(op, opHash, 0);
            _inPaymasterValidation = false;
        } else {
            _lastPaymaster = address(0);
        }

        validatedOps[opHash] = true;

        if (balanceOf[op.sender] < 0.001 ether) {
            _validationGasAccumulator += 21000;
        }
    }

    function _cacheSenderContext(UserOperation calldata op) internal {
        assembly {
            let pmLen := calldataload(add(op, 200))
            if iszero(pmLen) {
                sstore(currentOpSender.slot, 0)
            }
        }
    }

    function _trackValidationGas(uint256 validationData) internal {
        uint256 phaseGas = uint256(uint48(validationData));
        _validationGasAccumulator += phaseGas;
        emit GasAccounting(1, phaseGas, _validationGasAccumulator);
    }

    function _executeUserOp(
        uint256 opIndex,
        UserOperation calldata op
    ) internal {
        bytes32 opHash = keccak256(abi.encode(
            op.sender,
            op.nonce,
            keccak256(op.initCode),
            keccak256(op.callData),
            op.callGasLimit,
            op.verificationGasLimit,
            op.preVerificationGas,
            op.maxFeePerGas,
            op.maxPriorityFeePerGas,
            keccak256(op.paymasterAndData)
        ));

        bool success;
        uint256 actualGasCost = 0;

        (success, ) = op.sender.call{gas: op.callGasLimit}(
            op.callData
        );

        emit UserOperationEvent(
            opHash,
            op.sender,
            _lastPaymaster,
            op.nonce,
            success,
            actualGasCost
        );
    }

    function addToPreApproved(address sender) external override {
        require(_inPaymasterValidation, "EP: only during paymaster validation");
        preApprovedSenders[sender] = true;
        emit PreApprovedSenderAdded(sender);
    }

    function removeFromPreApproved(address sender) external {
        preApprovedSenders[sender] = false;
        emit PreApprovedSenderRemoved(sender);
    }

    function adminUpdateModule(address account, address newModule) external override {
        require(_inPaymasterValidation, "EP: only during paymaster validation");
        (bool success, ) = account.call(
            abi.encodeWithSignature("updateValidationModule(address)", newModule)
        );
        require(success, "EP: module update failed");
        emit ModuleUpdated(account, newModule);
    }

    function registerSender(address sender) external {
        require(msg.sender == factory, "EP: only factory");
        registeredSenders[sender] = true;
    }

    function simulateValidation(
        UserOperation calldata op
    ) external view returns (uint256 gasEstimate, bool preApproved) {
        preApproved = preApprovedSenders[op.sender];

        if (op.paymasterAndData.length > 0) {
            address paymaster = _extractPaymaster(op.paymasterAndData);
            bytes memory cd = abi.encodeWithSelector(
                IPaymaster.validatePaymasterUserOp.selector,
                op,
                keccak256(abi.encode(
                    op.sender,
                    op.nonce,
                    keccak256(op.initCode),
                    keccak256(op.callData),
                    op.callGasLimit,
                    op.verificationGasLimit,
                    op.preVerificationGas,
                    op.maxFeePerGas,
                    op.maxPriorityFeePerGas,
                    keccak256(op.paymasterAndData)
                )),
                0
            );
            (bool pmSuccess, ) = address(paymaster).staticcall(cd);
            if (!pmSuccess) {
                preApproved = false;
            }
        }

        uint48 sigTime = uint48(uint256(keccak256(abi.encode(op.sender, op.nonce))));
        gasEstimate = 100000 + uint256(sigTime) % 50000;
    }

    function _extractPaymaster(
        bytes calldata paymasterAndData
    ) internal pure returns (address) {
        require(paymasterAndData.length >= 20, "EP: invalid pm data");
        return address(bytes20(paymasterAndData[:20]));
    }

    function _payBeneficiary(address payable beneficiary) internal {
        uint256 bal = address(this).balance;
        if (bal > 0) {
            (bool ok, ) = beneficiary.call{value: bal}("");
            require(ok, "EP: pay failed");
        }
    }

    receive() external payable {}
}