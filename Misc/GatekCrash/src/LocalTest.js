// GateCrash — Local Test Script
// Connect to your RPC instance and query challenge state.

const { ethers } = require("ethers");

// ============ Configuration ============
const RPC_URL = process.env.RPC || "http://127.0.0.1:8545";

// ============ Setup ABI ============
const SETUP_ABI = [
    "function entryPoint() view returns (address)",
    "function factory() view returns (address)",
    "function adminAccount() view returns (address)",
    "function attackerAccount() view returns (address)",
    "function adminOwner() view returns (address)",
    "function attackerOwner() view returns (address)",
    "function isSolved() view returns (bool)",
];

// ============ UserOperation Struct ============
function createUserOperation(sender, nonce, callData, paymasterAndData, signature) {
    return {
        sender: sender,
        nonce: nonce,
        initCode: "0x",
        callData: callData,
        callGasLimit: 200000,
        verificationGasLimit: 300000,
        preVerificationGas: 50000,
        maxFeePerGas: 1000000000,
        maxPriorityFeePerGas: 1000000000,
        paymasterAndData: paymasterAndData || "0x",
        signature: signature || "0x"
    };
}

async function sendUserOperation(entryPointAddr, userOp, wallet) {
    const entryPointABI = [
        "function handleOps(tuple(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[] ops, address payable beneficiary) external"
    ];

    const entryPoint = new ethers.Contract(entryPointAddr, entryPointABI, wallet);

    console.log("[*] Sending UserOperation...");
    console.log(`    sender: ${userOp.sender}`);
    console.log(`    nonce:  ${userOp.nonce}`);

    const tx = await entryPoint.handleOps([userOp], wallet.address);
    const receipt = await tx.wait();

    console.log(`[+] TX completed: ${tx.hash}`);
    console.log(`    Gas used: ${receipt.gasUsed}`);
    return receipt;
}

async function getAccountInfo(provider, accountAddr) {
    const accountABI = [
        "function owner() view returns (address)",
        "function nonce() view returns (uint256)",
        "function validationModuleFlag() view returns (uint48)",
        "function validationModule() view returns (address)"
    ];
    const account = new ethers.Contract(accountAddr, accountABI, provider);
    const owner = await account.owner();
    const nonce = await account.nonce();
    const validationModuleFlag = await account.validationModuleFlag();
    const validationModule = await account.validationModule();
    return { owner, nonce, validationModuleFlag, validationModule };
}

// ============ Main ============
async function main() {
    console.log("=".repeat(50));
    console.log(" GateCrash — ERC-4337 Account Abstraction");
    console.log("=".repeat(50));
    console.log();

    const provider = new ethers.JsonRpcProvider(RPC_URL);

    const setupAddr = process.env.SETUP;
    if (!setupAddr) {
        console.log("[!] Please set SETUP environment variable to the Setup contract address");
        console.log("[!] Usage: export SETUP=<address provided by server>");
        return;
    }

    const setup = new ethers.Contract(setupAddr, SETUP_ABI, provider);
    const [entryPointAddr, adminAccount, attackerAccount, adminOwner, attackerOwner] =
        await Promise.all([
            setup.entryPoint(),
            setup.adminAccount(),
            setup.attackerAccount(),
            setup.adminOwner(),
            setup.attackerOwner(),
        ]);

    console.log("Deployment info (from Setup):");
    console.log(`  Setup:           ${setupAddr}`);
    console.log(`  EntryPoint:      ${entryPointAddr}`);
    console.log(`  Admin Account:   ${adminAccount}`);
    console.log(`  Admin Owner:     ${adminOwner}`);
    console.log(`  Attacker Account: ${attackerAccount}`);
    console.log(`  Attacker Owner:  ${attackerOwner}`);
    console.log(`  isSolved:        ${await setup.isSolved()}`);
    console.log();

    console.log("[*] Querying account info...");
    const adminInfo = await getAccountInfo(provider, adminAccount);
    const attackerInfo = await getAccountInfo(provider, attackerAccount);

    console.log(`  Admin Account:    owner=${adminInfo.owner}, nonce=${adminInfo.nonce}`);
    console.log(`  Admin Module:     ${adminInfo.validationModule}`);
    console.log(`  Attacker Account: owner=${attackerInfo.owner}, nonce=${attackerInfo.nonce}`);

    const adminBalance = await provider.getBalance(adminAccount);
    console.log(`  Admin Balance:   ${ethers.formatEther(adminBalance)} ETH`);
    console.log();

    console.log("=".repeat(50));
    console.log(" Use the provided RPC + private key to interact");
    console.log(" with the contracts and solve the challenge.");
    console.log("=".repeat(50));
}

main().catch(console.error);
