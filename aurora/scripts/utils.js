require('dotenv').config();
const hre = require("hardhat");

const {encodeInitMsgToBorsh} = require("../test/EncodeInitMsgToBorsh");

async function registerToken(signer, config, fastBridgeAddress, nearTokenAccountId) {
    const fastBridge = await getFastBridgeContract(signer, config, fastBridgeAddress);

    const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
    await wnear.approve(fastBridgeAddress, "2000000000000000000000000"); //storage deposit for creating implicit account

    await fastBridge.registerToken(nearTokenAccountId);

    console.log("Aurora Fast Bridge Account Id on Near: ", await fastBridge.getImplicitNearAccountIdForSelf());
}

async function storageDeposit(signer, config, fastBridgeAddress, nearTokenAccountId) {
    const fastBridge = await getFastBridgeContract(signer, config, fastBridgeAddress);

    const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
    await wnear.approve(fastBridgeAddress, "12500000000000000000000"); //token storage deposit

    await fastBridge.storageDeposit(nearTokenAccountId, "12500000000000000000000");
}

async function initTokenTransfer(signer, config, fastBridgeAddress, nearTokenAccountId, auroraTokenAddress, ethTokenAddress) {
    const usdc = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", auroraTokenAddress);
    await usdc.approve(fastBridgeAddress, "2000000000000000000000000");

    const fastBridge = await getFastBridgeContract(signer, config, fastBridgeAddress);

    let lockPeriod = 10800000000000;
    const validTill = Date.now() * 1000000 + lockPeriod;

    const initTokenTransferArg = encodeInitMsgToBorsh(validTill, nearTokenAccountId, ethTokenAddress.substring(2), 100, 100, signer.address, signer.address);

    const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
    await wnear.transfer(fastBridgeAddress, 1);

    const options = { gasLimit: 5000000 };
    let tx = await fastBridge.initTokenTransfer(initTokenTransferArg, options);
    await tx.wait();
}

async function unlock(signer, config, fastBridgeAddress, nonce, ethTokenAddress, validTillBlockHeight) {
    const fastBridge = await getFastBridgeContract(signer, config, fastBridgeAddress);
    
    const { getUnlockProof } = require('../test/UnlockProof');
    const proof = await getUnlockProof("0x00763f30eEB0eEF506907e18f2a6ceC2DAb30Df8",
        { token: ethTokenAddress,
          recipient: signer.address,
          nonce,
          amount: 100}, validTillBlockHeight);

    console.log("proof: ",  proof);
    console.log("proof len: ", proof.length);
    
    let tx = await fastBridge.unlock(nonce, proof);
    await tx.wait();
}

async function fast_bridge_withdraw_on_near(signer, config, fastBridgeAddress, nearTokenAccountId, amount) {
    const fastBridge = await getFastBridgeContract(signer, config, fastBridgeAddress);

    const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
    await wnear.transfer(fastBridgeAddress, 1);

    let tx = await fastBridge.fastBridgeWithdrawOnNear(nearTokenAccountId, amount);
    let receipt = await tx.wait();
}

async function withdraw_from_implicit_near_account(signer, config, fastBridgeAddress, nearTokenAccountId, accountAddress) {
    const fastBridge = await getFastBridgeContract(signer, config, fastBridgeAddress);

    const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
    await wnear.transfer(fastBridgeAddress, 1);

    let tx = await fastBridge.withdrawFromImplicitNearAccount(nearTokenAccountId, accountAddress);
    let receipt = await tx.wait();
}

async function get_implicit_near_account_id(signer, config, fastBridgeAddress) {
    const fastBridge = await getFastBridgeContract(signer, config, fastBridgeAddress);
    console.log("Aurora Fast Bridge Address on Near: ", await fastBridge.getImplicitNearAccountIdForSelf());
}

async function get_token_aurora_address(signer, config, fastBridgeAddress, nearTokenAccountId) {
    const fastBridge = await getFastBridgeContract(signer, config, fastBridgeAddress);
    console.log("Aurora Fast Bridge Address on Near: ", await fastBridge.getTokenAuroraAddress(nearTokenAccountId));
}

async function get_balance(signer, config, fastBridgeAddress, nearTokenAccountId) {
    const fastBridge = await getFastBridgeContract(signer, config, fastBridgeAddress);
    console.log("Token balance: ", await fastBridge.getUserBalance(nearTokenAccountId, signer.address));
}

async function set_whitelist_mode_for_users(signer, config, fastBridgeAddress, userAddress) {
    const fastBridge = await getFastBridgeContract(signer, config, fastBridgeAddress);

    let tx = await fastBridge.setWhitelistModeForUsers([userAddress], [true]);
    let receipt = await tx.wait();
}

async function setWhitelistMode(signer, config, fastBridgeAddress) {
  const fastBridge = await getFastBridgeContract(
    signer,
    config,
    fastBridgeAddress
  );
  let tx = await fastBridge.setWhitelistMode(false);
  let receipt = await tx.wait();
  console.log("Transaction hash: ", receipt.hash);
}

async function getFastBridgeContract(signer, config, fastBridgeAddress) {
    console.log("Sending transaction with the account:", signer.address);

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

exports.get_token_aurora_address = get_token_aurora_address;
exports.get_implicit_near_account_id = get_implicit_near_account_id;
exports.set_whitelist_mode_for_users = set_whitelist_mode_for_users;
exports.setWhitelistMode = setWhitelistMode;
exports.initTokenTransfer = initTokenTransfer;
exports.registerToken = registerToken;
exports.storageDeposit = storageDeposit;
exports.unlock = unlock;
exports.fast_bridge_withdraw_on_near = fast_bridge_withdraw_on_near;
exports.withdraw_from_implicit_near_account = withdraw_from_implicit_near_account;
exports.get_balance = get_balance;
