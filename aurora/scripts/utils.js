require('dotenv').config();
const hre = require("hardhat");

const WNEAR_AURORA_ADDRESS = "0x4861825E75ab14553E5aF711EbbE6873d369d146";

async function tokensRegistration(provider, fastBridgeAddress, nearTokenAddress, auroraTokenAddress) {
    const fast_bridge = await before_work_with_fast_bridge(provider, fastBridgeAddress);
    await fast_bridge.tokens_registration(auroraTokenAddress, nearTokenAddress);

    console.log("Aurora Fast Bridge Address on Near: ", await fast_bridge.get_near_address());
}

async function initTokenTransfer(provider, fastBridgeAddress, initTokenTransferArg, auroraTokenAddress) {
    const usdc = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", auroraTokenAddress);
    await usdc.approve(fastBridgeAddress, "2000000000000000000000000");

    const fast_bridge = await before_work_with_fast_bridge(provider, fastBridgeAddress);

    const options = { gasLimit: 5000000 };
    let tx = await fast_bridge.init_token_transfer(initTokenTransferArg, options);
    let receipt = await tx.wait();
    console.log(receipt.events[0].args);
}

async function unlock(provider, fastBridgeAddress, nonce) {
    const fast_bridge = await before_work_with_fast_bridge(provider, fastBridgeAddress);

    let tx = await fast_bridge.unlock(nonce);
    let receipt = await tx.wait();
    console.log(receipt.events[0].args);
}

async function withdraw_from_near(provider, fastBridgeAddress, nearTokenAddress, amount) {
    const fast_bridge = await before_work_with_fast_bridge(provider, fastBridgeAddress);

    let tx = await fast_bridge.withdraw_from_near(nearTokenAddress, amount);
    let receipt = await tx.wait();
}

async function withdraw(provider, fastBridgeAddress, nearTokenAddress) {
    const fast_bridge = await before_work_with_fast_bridge(provider, fastBridgeAddress);

    let tx = await fast_bridge.withdraw(nearTokenAddress);
    let receipt = await tx.wait();
}

async function before_work_with_fast_bridge(provider, fastBridgeAddress) {
    fastBridgeAddress = hre.ethers.utils.getAddress(fastBridgeAddress);
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);
    console.log("Sending transaction with the account:", deployerWallet.address);
    console.log("Account balance:", (await deployerWallet.getBalance()).toString());

    const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
    await wnear.approve(fastBridgeAddress, "4012500000000000000000000");

    const FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": process.env.AURORA_SDK_ADDRESS,
            "Utils": process.env.AURORA_UTILS_ADDRESS
        },
    });
    const fast_bridge = await FastBridge
        .attach(fastBridgeAddress)
        .connect(deployerWallet);

    return fast_bridge;
}

exports.initTokenTransfer = initTokenTransfer;
exports.tokensRegistration = tokensRegistration;
exports.unlock = unlock;
exports.withdraw_from_near = withdraw_from_near;
exports.withdraw = withdraw;

exports.WNEAR_AURORA_ADDRESS = WNEAR_AURORA_ADDRESS;