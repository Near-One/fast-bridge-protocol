const { ethers, upgrades } = require("hardhat");
const { getAddressSaver } = require("../utilities/helpers");
const { getImplementationAddress } = require("@openzeppelin/upgrades-core");
const path = require("path");

async function main() {
    const [deployer] = await ethers.getSigners();
    const network = (await ethers.getDefaultProvider().getNetwork()).name;
    const addressesPath = path.join(__dirname, "./deploymentAddresses.json");
    const saveAddress = getAddressSaver(addressesPath, network, true);
    const tokensAddresses = Object.values(require("./deploymentAddresses.json").tokens);
    const whitelistedTokens = Object.values(require("./deploymentAddresses.json").whitelisted_tokens);
    const bridge = (await ethers.getContractFactory("EthErc20FastBridge")).connect(deployer);
    let proxy = await upgrades.deployProxy(bridge, [tokensAddresses, whitelistedTokens], { 
        initializer: "initialize" 
    });
    await proxy.deployed();

    saveAddress("bridge", proxy.address);

    const currentImplAddress = await getImplementationAddress(ethers.provider, proxy.address);

    saveAddress("bridge_implementation", currentImplAddress); // save implementation address

    console.log("Deployment is completed.");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

exports.deployBridge = main
