const { ethers, upgrades } = require("hardhat");
const { getImplementationAddress } = require("@openzeppelin/upgrades-core");
require("dotenv");
// const { argv } = require("process");

async function main() {
    const [deployer] = await ethers.getSigners();

    const EthErc20FastBridge = await ethers.getContractFactory("EthErc20FastBridge", deployer);
    const bridgeaddress = process.env.BRIDGE_PROXY_ADDRESS;
    console.log(bridgeaddress);
    console.log("Need to upgrade bridge?");
    console.log("Proxy provided : ", bridgeaddress);

    process.stdout.write("Ok to proceed? (y/n) : ");
    process.stdin.on("readable", async () => {
        const chunk = process.stdin.read();
        if (chunk !== null) {
            let userInput = chunk.toString().trim().toLowerCase();
            if (userInput === "y") {
                // Perform the upgrade
                console.log("Performing the upgrade...");
                await upgrades.upgradeProxy(
                    bridgeaddress, // address of proxy deployed
                    EthErc20FastBridge,
                    {
                        unsafeAllow: ["delegatecall"]
                    }
                );
                const currentImplAddress = await getImplementationAddress(ethers.provider, bridgeaddress);
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
