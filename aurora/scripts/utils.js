require('dotenv').config();
const hre = require("hardhat");
const {encodeInitMsgToBorsh} = require("../test/EncodeInitMsgToBorsh");

async function tokensRegistration(signer, config, fastBridgeAddress, nearTokenAddress, auroraTokenAddress) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);
    await fastBridge.registerToken(auroraTokenAddress, nearTokenAddress);

    console.log("Aurora Fast Bridge Address on Near: ", await fastBridge.getNearAddress());
}

async function initTokenTransfer(signer, config, fastBridgeAddress, nearTokenAddress, auroraTokenAddress, ethTokenAddress) {
    const usdc = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", auroraTokenAddress);
    await usdc.approve(fastBridgeAddress, "2000000000000000000000000");

    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);
    
    

    let lockPeriod = 10800000000000;
    const validTill = Date.now() * 1000000 + lockPeriod;

    const initTokenTransferArg = encodeInitMsgToBorsh(validTill, nearTokenAddress, ethTokenAddress.substring(2), 100, 100, signer.address, signer.address);
     
    const options = { gasLimit: 5000000 };
    let tx = await fastBridge.initTokenTransfer(initTokenTransferArg, options);
    let receipt = await tx.wait();
    console.log(receipt.events[0].args);
}

async function unlock(signer, config, fastBridgeAddress, nonce, ethTokenAddress, validTillBlockHeight) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);
    
    const { getUnlockProof } = require('../test/UnlockProof');
    const proof = await getUnlockProof("0x00763f30eEB0eEF506907e18f2a6ceC2DAb30Df8",
        { token: ethTokenAddress,
          recipient: signer.address,
          nonce,
          amount: 100}, validTillBlockHeight);

    console.log("proof: ",  proof);
    console.log("proof len: ", proof.length);
    
    let tx = await fastBridge.unlock(nonce, proof);
    let receipt = await tx.wait();
    //console.log(receipt.events[0].args);
}

async function withdraw_from_near(signer, config, fastBridgeAddress, nearTokenAddress, amount) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);

    console.log("Withdraw from Near");
    let tx = await fastBridge.withdrawFromNear(nearTokenAddress, amount);
    let receipt = await tx.wait();
}

async function withdraw(signer, config, fastBridgeAddress, nearTokenAddress) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);

    let tx = await fastBridge.withdraw(nearTokenAddress);
    let receipt = await tx.wait();
}


async function get_near_account_id(signer, config, fastBridgeAddress) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);
    console.log("Aurora Fast Bridge Address on Near: ", await fastBridge.getNearAddress());
}

async function get_token_aurora_address(signer, config, fastBridgeAddress, nearTokenAddress) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);
    console.log("Aurora Fast Bridge Address on Near: ", await fastBridge.getTokenAuroraAddress(nearTokenAddress));
}


async function get_balance(signer, config, fastBridgeAddress, nearTokenAccountId) {
    const fastBridge = await beforeWorkWithFastBridge(signer, config, fastBridgeAddress);
    console.log("Token balance: ", await fastBridge.getUserBalance(nearTokenAccountId, signer.address));
}

async function beforeWorkWithFastBridge(signer, config, fastBridgeAddress) {
    console.log("Sending transaction with the account:", signer.address);

    const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", config.wNearAddress);
    await wnear.approve(fastBridgeAddress, "4012500000000000000000000");
    
    await wnear.transfer(fastBridgeAddress, 1);
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
exports.get_near_account_id = get_near_account_id;
exports.initTokenTransfer = initTokenTransfer;
exports.tokensRegistration = tokensRegistration;
exports.unlock = unlock;
exports.withdraw_from_near = withdraw_from_near;
exports.withdraw = withdraw;
exports.get_balance = get_balance;
