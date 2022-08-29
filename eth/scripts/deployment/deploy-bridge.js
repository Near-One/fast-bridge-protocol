const { ethers, upgrades} =  require("hardhat");
const { verify, getAddressSaver } = require("./utilities/helpers");
const path = require("path");

async function main() {
    const [deployer] = await ethers.getSigners();
    const network = (await ethers.getDefaultProvider().getNetwork()).name;
    const addressesPath = path.join(__dirname, "./deploymentAddresses.json");
    const saveAddress = getAddressSaver(addressesPath, network, true);

    const tokensAddresses = Object.values(require('./deploymentAddresses.json').tokens);
    const whitelistedTokens = Object.values(require('./deploymentAddresses.json').whitelisted_tokens);
    const bridge = (await ethers.getContractFactory("EthErc20FastBridge")).connect(deployer);
    let proxy = await upgrades.deployProxy(bridge, [tokensAddresses, whitelistedTokens], { unsafeAllow: ['delegatecall'] });
    await proxy.deployed();

    saveAddress("bridge", proxy.address);
    console.log("Deployment is completed.");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
