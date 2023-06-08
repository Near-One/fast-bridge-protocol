const { ethers, upgrades } = require("hardhat");
const { getImplementationAddress } = require("@openzeppelin/upgrades-core");
require("dotenv");

async function main() {
    const [deployer] = await ethers.getSigners();

    const EthErc20FastBridge = await ethers.getContractFactory("EthErc20FastBridge", deployer);
    const bridgeProxyAddress = process.env.BRIDGE_PROXY_ADDRESS;
    console.log("Need to upgrade bridge?");
    console.log("Proxy provided : ", bridgeProxyAddress);

    process.stdout.write("Ok to proceed? (y/n) : ");
    process.stdin.on("readable", async () => {
        const chunk = process.stdin.read();
        if (chunk !== null) {
            let userInput = chunk.toString().trim().toLowerCase();
            if (userInput === "y") {
                // Perform the upgrade
                console.log("Performing the upgrade...");
                if (process.env.FORCE_IMPORT_PROXY) {
                    // FORCE_IMPORT_PROXY must be the contract factory of the current implementation 
                    // contract version that is being used, not the version that you are planning to upgrade to.
                    const EthErc20FastBridgeV1 = await ethers.getContractFactory(process.env.FORCE_IMPORT_PROXY, deployer);
                    await upgrades.forceImport(bridgeProxyAddress, EthErc20FastBridgeV1);
                }
                const proxy = await upgrades.upgradeProxy(
                    bridgeProxyAddress, // address of proxy deployed
                    EthErc20FastBridge
                );
                await proxy.deployed();

                const currentImplAddress = await getImplementationAddress(ethers.provider, bridgeProxyAddress);
                console.log("EthErc20FastBridge upgraded");
                console.log("Current implementation address is ", currentImplAddress);
            } else if (userInput === "n") {
                // Do not upgrade
                console.log("Bridge upgrade cancelled.");
            } else {
                // Handle invalid input
                console.log("Invalid input.");
            }
        }
    });
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
