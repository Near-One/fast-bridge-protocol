const { ethers } = require("hardhat");
const deploymentAddress = require("../deployment/deploymentAddresses.json");

async function getBridge() {
    const network = (await ethers.getDefaultProvider().getNetwork()).name;

    const bridgeAddress = deploymentAddress[network].new.bridge_proxy;
    const bridge = ethers.getContractAt("/contracts/EthErc20FastBridge.sol:EthErc20FastBridge", bridgeAddress);

    return bridge;
}

async function bulkWhitelistStatusUpdate(tokensArray, statusArray, signer) {
    const bridge = await getBridge();
    await bridge.connect(signer).setWhitelistedTokens(tokensArray, statusArray);
}

async function addTokenToWhitelist(token, signer) {
    const bridge = await getBridge();
    await bridge.connect(signer).addTokenToWhitelist(token);
}

async function removeTokenFromWhitelist(token, signer) {
    const bridge = await getBridge();
    await bridge.connect(signer).removeTokenFromWhitelist(token);
}

async function isTokenInWhitelist(token) {
    const bridge = await getBridge();
    await bridge.isTokenInWhitelist(token);
}

module.exports = {
    getBridge,
    isTokenInWhitelist,
    removeTokenFromWhitelist,
    addTokenToWhitelist,
    bulkWhitelistStatusUpdate
};
