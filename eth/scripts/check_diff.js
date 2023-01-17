const { ethers } = require("hardhat");
const hre = require("hardhat");

// const path = require("path");

async function main() {
    // get local bytecode
    const localBytecode = (await hre.artifacts.readArtifact("contracts/EthErc20FastBridge_flat.sol:EthErc20FastBridge"))
        .bytecode;

    // get deployed bytecode
    const contractAddress = ""; // replace with the address of the deployed contract
    const deployedBytecode = await ethers.provider.getCode(contractAddress);
    console.log(deployedBytecode);

    // check  bytecodes are same
    if (localBytecode != deployedBytecode) {
        // fail CI
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
