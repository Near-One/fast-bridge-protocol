require('dotenv').config();
const hre = require("hardhat");

const WNEAR_AURORA_ADDRESS = "0x4861825E75ab14553E5aF711EbbE6873d369d146";

async function tokensRegistration(provider, fastBridgeAddress, nearTokenAddress, auroraTokenAddress) {
    fastBridgeAddress = hre.ethers.utils.getAddress(fastBridgeAddress);
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    console.log("Sending transaction with the account:", deployerWallet.address);
    console.log("Account balance:", (await deployerWallet.getBalance()).toString());

    const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
    await wnear.approve(fastBridgeAddress, "4012500000000000000000000");

    const FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": "0x425cA8f218784ebE2df347E98c626094B63E7f30",
            "Utils": "0xc129336a6995F3b70A7139585403B82098260172"
        },
    });
    const fast_bridge = await FastBridge
        .attach(fastBridgeAddress)
        .connect(deployerWallet);

    let tx = await fast_bridge.tokens_registration(auroraTokenAddress, nearTokenAddress);
    let receipt = await tx.wait();

    console.log("Aurora Fast Bridge Address on Near: ", receipt.events[0].args);
}

async function initTokenTransfer(provider, fastBridgeAddress, initTokenTransferArg, auroraTokenAddress) {
    fastBridgeAddress = hre.ethers.utils.getAddress(fastBridgeAddress);
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    console.log("Sending transaction with the account:", deployerWallet.address);
    console.log("Account balance:", (await deployerWallet.getBalance()).toString());

    const usdc = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", auroraTokenAddress);
    await usdc.approve(fastBridgeAddress, "2000000000000000000000000");

    const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
    await wnear.approve(fastBridgeAddress, "2000000000000000000000000");

    const FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": "0x425cA8f218784ebE2df347E98c626094B63E7f30",
            "Utils": "0xc129336a6995F3b70A7139585403B82098260172"
        },
    });
    const fast_bridge = await FastBridge
        .attach(fastBridgeAddress)
        .connect(deployerWallet);

    let tx = await fast_bridge.init_token_transfer(initTokenTransferArg);
    let receipt = await tx.wait();
    console.log(receipt.events[0].args);
}

async function unlock(provider, fastBridgeAddress, nonce) {
    fastBridgeAddress = hre.ethers.utils.getAddress(fastBridgeAddress);
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    console.log("Sending transaction with the account:", deployerWallet.address);
    console.log("Account balance:", (await deployerWallet.getBalance()).toString());

    const FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": "0x425cA8f218784ebE2df347E98c626094B63E7f30",
            "Utils": "0xc129336a6995F3b70A7139585403B82098260172"
        },
    });
    const fast_bridge = await FastBridge
        .attach(fastBridgeAddress)
        .connect(deployerWallet);

    let tx = await fast_bridge.unlock(nonce);
    let receipt = await tx.wait();
    console.log(receipt.events[0].args);
}

async function withdraw(provider, fastBridgeAddress, nearTokenAddress) {
    fastBridgeAddress = hre.ethers.utils.getAddress(fastBridgeAddress);
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
    await wnear.approve(fastBridgeAddress, "2000000000000000000000000");

    const FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": "0x425cA8f218784ebE2df347E98c626094B63E7f30",
            "Utils": "0xc129336a6995F3b70A7139585403B82098260172"
        },
    });
    const fast_bridge = await FastBridge
        .attach(fastBridgeAddress)
        .connect(deployerWallet);

    let tx = await fast_bridge.withdraw(nearTokenAddress);
    let receipt = await tx.wait();
}

async function withdraw_from_near(provider, fastBridgeAddress, nearTokenAddress, amount) {
    fastBridgeAddress = hre.ethers.utils.getAddress(fastBridgeAddress);
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
    await wnear.approve(fastBridgeAddress, "2000000000000000000000000");

    const FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": "0x425cA8f218784ebE2df347E98c626094B63E7f30",
            "Utils": "0xc129336a6995F3b70A7139585403B82098260172"
        },
    });
    const fast_bridge = await FastBridge
        .attach(fastBridgeAddress)
        .connect(deployerWallet);

    let tx = await fast_bridge.withdraw_from_near(nearTokenAddress, amount);
    let receipt = await tx.wait();
}

exports.initTokenTransfer = initTokenTransfer;
exports.tokensRegistration = tokensRegistration;
exports.withdraw = withdraw;
exports.unlock = unlock;
exports.withdraw_from_near = withdraw_from_near;

exports.WNEAR_AURORA_ADDRESS = WNEAR_AURORA_ADDRESS;