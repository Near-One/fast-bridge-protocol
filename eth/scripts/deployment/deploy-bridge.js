const { ethers, upgrades, network } = require("hardhat");
const { verify, getAddressSaver } = require("./utilities/helpers");
const { getImplementationAddress } = require("@openzeppelin/upgrades-core");
const path = require("path");

async function deploy_fast_bridge(verification) {
    const [deployer] = await ethers.getSigners();
    const network_name = network.name;

    const addressesPath = path.join(__dirname, "./deploymentAddresses.json");
    const saveAddress = getAddressSaver(addressesPath, network_name, true);

    const tokensAddresses = Object.values(require("./deploymentAddresses.json").tokens);
    const whitelistedTokens = Object.values(require("./deploymentAddresses.json").whitelisted_tokens);
    const bridge = (await ethers.getContractFactory("EthErc20FastBridge")).connect(deployer);
    let proxy = await upgrades.deployProxy(bridge, [tokensAddresses, whitelistedTokens], {
        initializer: "initialize"
    });
    await proxy.deployed();

    saveAddress("bridge_proxy", proxy.address);
    console.log("Deployment is completed.");
    const currentImplAddress = await getImplementationAddress(ethers.provider, proxy.address);
    saveAddress("bridge_Implementation", currentImplAddress); // save implementation address

    if (verification) {
        // verify-contract
        console.log("Verifing Contract");
        await verify(proxy.address, []);
        console.log("<< Contract Verified Successfully >>.");
    }
}

module.exports = deploy_fast_bridge;
