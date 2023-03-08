// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
require('dotenv').config();
const hre = require("hardhat");
const {WNEAR_AURORA_ADDRESS} = require("./utils");
const NEAR_FAST_BRIDGE_ADDRESS="fb.olga24912_3.testnet"

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

    console.log(
        "Account balance:",
        (await deployerWallet.getBalance()).toString()
    );

    const AuroraErc20FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": "0x425cA8f218784ebE2df347E98c626094B63E7f30",
            "Utils": "0xc129336a6995F3b70A7139585403B82098260172"
        },
    });
    const options = { gasLimit: 6000000 };
    const fastbridge = await AuroraErc20FastBridge.connect(deployerWallet)
        .deploy(WNEAR_AURORA_ADDRESS, NEAR_FAST_BRIDGE_ADDRESS, options);
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
