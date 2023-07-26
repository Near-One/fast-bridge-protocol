require('dotenv').config();
const hre = require("hardhat");

const WNEAR_AURORA_ADDRESS = "0x4861825E75ab14553E5aF711EbbE6873d369d146";

async function tokensRegistration(provider, fastBridgeAddress, nearTokenAddress, auroraTokenAddress) {
    const fastBridge = await beforeWorkWithFastBridge(provider, fastBridgeAddress);
    await fastBridge.tokensRegistration(auroraTokenAddress, nearTokenAddress);

    console.log("Aurora Fast Bridge Address on Near: ", await fastBridge.getNearAddress());
}

async function initTokenTransfer(provider, fastBridgeAddress, initTokenTransferArg, auroraTokenAddress) {
    const usdc = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", auroraTokenAddress);
    await usdc.approve(fastBridgeAddress, "2000000000000000000000000");

    const fastBridge = await beforeWorkWithFastBridge(provider, fastBridgeAddress);

    const options = { gasLimit: 5000000 };
    let tx = await fastBridge.initTokenTransfer(initTokenTransferArg, options);
    let receipt = await tx.wait();
    console.log(receipt.events[0].args);
}

async function unlock(provider, fastBridgeAddress, nonce) {
    const fastBridge = await beforeWorkWithFastBridge(provider, fastBridgeAddress);

    let tx = await fastBridge.unlock(nonce);
    let receipt = await tx.wait();
    console.log(receipt.events[0].args);
}

async function withdraw_from_near(provider, fastBridgeAddress, nearTokenAddress, amount) {
    const fastBridge = await beforeWorkWithFastBridge(provider, fastBridgeAddress);

    let tx = await fastBridge.withdrawFromNear(nearTokenAddress, amount);
    let receipt = await tx.wait();
}

async function withdraw(provider, fastBridgeAddress, nearTokenAddress) {
    const fastBridge = await beforeWorkWithFastBridge(provider, fastBridgeAddress);

    let tx = await fastBridge.withdraw(nearTokenAddress);
    let receipt = await tx.wait();
}

async function beforeWorkWithFastBridge(provider, fastBridgeAddress) {
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);
    console.log("Sending transaction with the account:", deployerWallet.address);

    const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
    await wnear.approve(fastBridgeAddress, "4012500000000000000000000");

    const FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": process.env.AURORA_SDK_ADDRESS,
            "Utils": process.env.AURORA_UTILS_ADDRESS
        },
    });

    return FastBridge
        .attach(fastBridgeAddress)
        .connect(deployerWallet);
}

exports.initTokenTransfer = initTokenTransfer;
exports.tokensRegistration = tokensRegistration;
exports.unlock = unlock;
exports.withdraw_from_near = withdraw_from_near;
exports.withdraw = withdraw;

exports.WNEAR_AURORA_ADDRESS = WNEAR_AURORA_ADDRESS;