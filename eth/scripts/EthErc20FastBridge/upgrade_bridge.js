const { ethers, upgrades, network } = require("hardhat");
const { getImplementationAddress } = require("@openzeppelin/upgrades-core");
const deploymentAddress = require("../deployment/deploymentAddresses.json");
const { getAddressSaver } = require("../deployment/utilities/helpers.js");
const path = require("path");
require("dotenv");

async function main(defaultAdminSigner) {
    const EthErc20FastBridge = await ethers.getContractFactory("EthErc20FastBridge", defaultAdminSigner);
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
                    const EthErc20FastBridgeV1 = await ethers.getContractFactory(
                        process.env.FORCE_IMPORT_PROXY,
                        defaultAdminSigner
                    );
                    await upgrades.forceImport(bridgeProxyAddress, EthErc20FastBridgeV1);
                }
                const proxy = await upgrades.upgradeProxy(
                    bridgeProxyAddress, // address of proxy deployed
                    EthErc20FastBridge
                );
                await proxy.deployed();

                const currentImplAddress = await getImplementationAddress(ethers.provider, proxy.address);
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

async function upgradeFastBridge(defaultAdminSigner) {
    const EthErc20FastBridge = await ethers.getContractFactory("EthErc20FastBridge", defaultAdminSigner);
    const network_name = network.name;
    const bridgeProxyAddress = deploymentAddress[network_name].new.bridge_proxy;
    const addressesPath = path.join(__dirname, "../deployment/deploymentAddresses.json");
    const saveAddress = getAddressSaver(addressesPath, network_name, true);
    const newBridge = await upgrades.upgradeProxy(bridgeProxyAddress, EthErc20FastBridge);
    await newBridge.deployed();
    saveAddress("bridge_proxy", newBridge.address);
    console.log("Fast-Bridge upgraded");
    const newBridgeImplementationAddress = await getImplementationAddress(ethers.provider, newBridge.address);
    saveAddress("bridge_Implementation", newBridgeImplementationAddress);
}

module.exports = { upgradeFastBridge };
