const { ethers, upgrades } = require("hardhat");
const { getAddressSaver } = require("../utilities/helpers");
const path = require("path");
const { test } = require("mocha");

async function main() {
    const [deployer] = await ethers.getSigners();
    const network = (await ethers.getDefaultProvider().getNetwork()).name;
    const addressesPath = path.join(__dirname, "./deploymentAddresses.json");
    const saveAddress = getAddressSaver(addressesPath, network, true);

    const TestToken = (await ethers.getContractFactory("TestToken")).connect(deployer);

    const usdcDecimals = 6;
    const wbtcDecimals = 8;
    const wethDecimals = 18;

    const testUSDC = await TestToken.deploy(usdcDecimals, "TEST_USDC", "TUSDC");
    await testUSDC.deployed();
    const testWBTC = await TestToken.deploy(wbtcDecimals, "TEST_WBTC", "TWBTC");
    await testWBTC.deployed();
    const testWETH = await TestToken.deploy(wethDecimals, "TEST_WETH", "TWETH");
    await testWETH.deployed();

    console.log(`TEST USDC at ${testUSDC.address}`);
    console.log(`TEST WBTC at ${testWBTC.address}`);
    console.log(`TEST WETH at ${testWETH.address}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

exports.deployTestToken = main