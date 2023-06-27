const { ethers, network } = require("hardhat");
const deploymentAddress = require("../deployment/deploymentAddresses.json");

async function getBridgeContract() {
    console.log("Connecting with bridge...");
    const network_name = network.name;
    const bridgeProxyAddress = deploymentAddress[network_name].new.bridge_proxy;
    const bridge = ethers.getContractAt("/contracts/EthErc20FastBridge.sol:EthErc20FastBridge", bridgeProxyAddress);
    console.log("Connected !");
    return bridge;
}

async function bulkWhitelistStatusUpdate(tokensArray, statusArray, signer) {
    let bridge;
    try {
        bridge = await getBridgeContract();
        await bridge.connect(signer).setWhitelistedTokens(tokensArray, statusArray);
        console.log("Bulk update for given tokens completed successfully");
    } catch (error) {
        console.error("Failed with error ", error);
    }
}

async function addTokenToWhitelist(token, signer) {
    let bridge;
    try {
        bridge = await getBridgeContract();
        await bridge.connect(signer).addTokenToWhitelist(token);
        console.log(token, "added to whitelist!");
    } catch (error) {
        console.error("Failed with error :", error);
    }
}

async function removeTokenFromWhitelist(token, signer) {
    let bridge;
    try {
        bridge = await getBridgeContract();
        await bridge.connect(signer).removeTokenFromWhitelist(token);
        console.log(token, "removed from whitelist!");
    } catch (error) {
        console.error("Failed with error :", error);
    }
}

async function isTokenInWhitelist(token) {
    let bridge;
    try {
        bridge = await getBridgeContract();
        (await bridge.isTokenInWhitelist(token))
            ? console.log(token, "is whitelisted")
            : console.log(token, "is not whitelisted");
    } catch (error) {
        console.error("Failed with error :", error);
    }
}

module.exports = {
    getBridgeContract,
    isTokenInWhitelist,
    removeTokenFromWhitelist,
    addTokenToWhitelist,
    bulkWhitelistStatusUpdate
};
