// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
require('dotenv').config();
const hre = require("hardhat");
const {WNEAR_AURORA_ADDRESS} = require("./utils");

async function main() {
    // Hardhat always runs the compile task when running scripts with its command
    // line interface.
    //
    // If this script is run directly using `node` you may want to call compile
    // manually to make sure everything is compiled
    // await hre.run('compile');

    const provider = hre.ethers.provider;
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    console.log(
        "Deploying contracts with the account:",
        deployerWallet.address
    );

    const AuroraErc20FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": process.env.AURORA_SDK_ADDRESS,
            "Utils": process.env.AURORA_UTILS_ADDRESS
        },
    });
    const options = { gasLimit: 6000000 };
    const fastbridge = await AuroraErc20FastBridge.connect(deployerWallet)
        .deploy(WNEAR_AURORA_ADDRESS, process.env.NEAR_FAST_BRIDGE_ACCOUNT, "aurora", options);
    await fastbridge.deployed();

    console.log("AuroraErc20FastBridge deployed to:", fastbridge.address);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });
