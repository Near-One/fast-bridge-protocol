const { ethers, upgrades } = require("hardhat");

async function bridge_deployment_task() {
    const usdcDecimals = 6;
    const [bridge_deployer, token_deployer] = await ethers.getSigners();
    const tokenInstance = (await ethers.getContractFactory("TestToken")).connect(token_deployer);
    let MockToken = await tokenInstance.deploy(usdcDecimals, "TEST_TOKEN", "MT");
    await MockToken.deployed();

    const bridge = (await ethers.getContractFactory("EthErc20FastBridge")).connect(bridge_deployer);
    let proxy = await upgrades.deployProxy(bridge, [[MockToken.address], [true]], {
        unsafeAllow: ["delegatecall"]
    });
    await proxy.deployed();

    const bridge_implementation_address = await upgrades.erc1967.getImplementationAddress(proxy.address);
    console.log("Deployment is completed.");
    console.log("Proxy FastBridge Deployed at: ", proxy.address);
    console.log("FastBridge Implemenation Address: ", bridge_implementation_address);
    console.log("Proxy FastBridge Deployed by address: ", bridge_deployer.address);
    console.log("Token Address: ", MockToken.address);
    console.log("Mock Token deployed by address: ", token_deployer.address);
}

module.exports = bridge_deployment_task;
