const { ethers, upgrades } = require("hardhat");
const { getImplementationAddress } = require("@openzeppelin/upgrades-core");

async function main() {
    const [deployer] = await ethers.getSigners();

    const BridgeAddress = "0x8d4c0531F6A7e0dA759A6675A38127EBcf5c2AA5";

    const EthErc20FastBridge = await ethers.getContractFactory("EthErc20FastBridge", deployer);

    console.log("Need to upgrade bridge?");
    console.log("Proxy provided : ", BridgeAddress);

    process.stdout.write("Ok to proceed? (y/n) : ");
    process.stdin.on("readable", async () => {
        const chunk = process.stdin.read();
        if (chunk !== null) {
            let userInput = chunk.toString().trim().toLowerCase();
            if (userInput === "y") {
                // Perform the upgrade
                console.log("Performing the upgrade...");
                await upgrades.upgradeProxy(
                    BridgeAddress, // address of proxy deployed
                    EthErc20FastBridge,
                    {
                        unsafeAllow: ["delegatecall"]
                    }
                );
                const currentImplAddress = await getImplementationAddress(ethers.provider, BridgeAddress);
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
