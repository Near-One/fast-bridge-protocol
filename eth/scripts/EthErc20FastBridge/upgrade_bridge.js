const { ethers, upgrades } = require("hardhat");
const deploymentAddress = require("../deployment/deploymentAddresses.json");

async function main() {
    const network = (await ethers.getDefaultProvider().getNetwork()).name;
    const [deployer] = await ethers.getSigners();

    const BridgeAddress = deploymentAddress[network].new.bridge_proxy;
    const EthErc20FastBridge = await ethers.getContractFactory(
        "/contracts/EthErc20FastBridge.sol:EthErc20FastBridge",
        deployer
    );
    console.log("Upgrading Bridge...");

    await upgrades.upgradeProxy(
        BridgeAddress, // address of proxy deployed
        EthErc20FastBridge,
        {
            unsafeAllow: ["delegatecall"]
        }
    );
    console.log("EthErc20FastBridge upgraded");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
