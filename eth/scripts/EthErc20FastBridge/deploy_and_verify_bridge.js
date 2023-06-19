const { ethers, upgrades } = require("hardhat");
const { getAddressSaver, verify } = require("../deployment/utilities/helpers");
const { getImplementationAddress } = require("@openzeppelin/upgrades-core");
const path = require("path");

const main = async () => {
    const [deployer] = await ethers.getSigners();
    const network = (await ethers.getDefaultProvider().getNetwork()).name;
    const addressesPath = path.join(__dirname, "../deployment/deploymentAddresses.json");
    const saveAddress = getAddressSaver(addressesPath, network, true);

    const tokensAddresses = Object.values(require("../deployment/deploymentAddresses.json").tokens);
    const whitelistedTokens = Object.values(require("../deployment/deploymentAddresses.json").whitelisted_tokens);

    const bridge = await ethers.getContractFactory("EthErc20FastBridge", deployer);
    const Bridge = await upgrades.deployProxy(bridge, [tokensAddresses, whitelistedTokens], {
        unsafeAllow: ["delegatecall"]
    });
    await Bridge.deployed();

    saveAddress("bridge_proxy", Bridge.address); // save bridge address

    const currentImplAddress = await getImplementationAddress(ethers.provider, Bridge.address);

    saveAddress("bridge_Implementation", currentImplAddress); // save implementation address

    // verify
    console.log("Verifing Contract");
    await verify(Bridge.address, [tokensAddresses, whitelistedTokens]);
    console.log("Verified.");
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
