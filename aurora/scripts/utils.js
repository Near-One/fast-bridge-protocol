require('dotenv').config();
const hre = require("hardhat");

async function registerToken(signer, config, fastBridgeAddress, nearTokenAccountId, auroraTokenAddress) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);
    await fastBridge.registerToken(auroraTokenAddress, nearTokenAccountId);

    console.log("Aurora Fast Bridge Account Id on Near: ", await fastBridge.getNearAccountId());
}

async function initTokenTransfer(signer, config, fastBridgeAddress, initTokenTransferArg, auroraTokenAddress) {
    const usdc = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", auroraTokenAddress);
    await usdc.approve(fastBridgeAddress, "2000000000000000000000000");

    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);

    const options = { gasLimit: 5000000 };
    let tx = await fastBridge.initTokenTransfer(initTokenTransferArg, options);
    let receipt = await tx.wait();
    console.log(receipt.events[0].args);
}

async function unlock(signer, config, fastBridgeAddress, nonce) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);

    let tx = await fastBridge.unlock(nonce);
    let receipt = await tx.wait();
    console.log(receipt.events[0].args);
}

async function withdraw_from_near(signer, config, fastBridgeAddress, nearTokenAccountId, amount) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);

    let tx = await fastBridge.withdrawFromNear(nearTokenAccountId, amount);
    let receipt = await tx.wait();
}

async function withdraw(signer, config, fastBridgeAddress, nearTokenAccountId) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);

    let tx = await fastBridge.withdraw(nearTokenAccountId);
    let receipt = await tx.wait();
}

async function set_whitelist_mode_for_users(signer, config, fastBridgeAddress, userAddress) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);

    let tx = await fastBridge.setWhitelistModeForUsers([userAddress], [true]);
    let receipt = await tx.wait();
}

async function setWhitelistMode(signer, config, fastBridgeAddress) {
  const fastBridge = await beforeWorkWithFastBridge(
    signer,
    config,
    fastBridgeAddress
  );
  let tx = await fastBridge.setWhitelistMode(false);
  let receipt = await tx.wait();
  console.log("Transaction hash: ", receipt.hash);
}

async function beforeWorkWithFastBridge(signer, config, fastBridgeAddress) {
    console.log("Sending transaction with the account:", signer.address);

    const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
    await wnear.approve(fastBridgeAddress, "4012500000000000000000000");

    const FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": config.auroraSdkAddress,
            "Utils": config.auroraUtilsAddress
        },
    });

    return FastBridge
        .attach(fastBridgeAddress)
        .connect(signer);
}

exports.set_whitelist_mode_for_users = set_whitelist_mode_for_users;
exports.setWhitelistMode = setWhitelistMode;
exports.initTokenTransfer = initTokenTransfer;
exports.registerToken = registerToken;
exports.unlock = unlock;
exports.withdraw_from_near = withdraw_from_near;
exports.withdraw = withdraw;
