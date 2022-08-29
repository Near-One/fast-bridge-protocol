const { ethers, upgrades} =  require("hardhat");
const { verify, getAddressSaver } = require("./utilities/helpers");
const path = require("path");

async function main() {
    const [deployer] = await ethers.getSigners();
    const network = (await ethers.getDefaultProvider().getNetwork()).name;
    const addressesPath = path.join(__dirname, "./deploymentAddresses.json");
    const saveAddress = getAddressSaver(addressesPath, network, true);

    const TestToken = (await ethers.getContractFactory("TestToken")).connect(deployer);

    const testUSDC = await TestToken.deploy(6, "TEST_USDC", "TUSDC");
    const testWBTC = await TestToken.deploy(8, "TEST_WBTC", "TWBTC");
    const testWETH = await TestToken.deploy(18, "TEST_WETH", "TWETH");
    
    console.log(`TEST USDC at ${testUSDC.address}`);
    console.log(`TEST WBTC at ${testWBTC.address}`);
    console.log(`TEST WETH at ${testWETH.address}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
