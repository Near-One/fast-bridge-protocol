const { ethers, upgrades } = require("hardhat");

async function main() {
    const [deployer] = await ethers.getSigners();
    const Token = await ethers.getContractFactory("TestToken");
    const tokenDeployed = await Token.deploy(18, "ETH", "ETH");
    await tokenDeployed.deployed();

    const bridge = (await ethers.getContractFactory("EthErc20FastBridge")).connect(deployer);
    let proxy = await upgrades.deployProxy(bridge, [[tokenDeployed.address], [true]], {
        unsafeAllow: ["delegatecall"]
    });
    await proxy.deployed();

    const bridge_implementation_address = await upgrades.erc1967.getImplementationAddress(proxy.address);
    console.log("Deployment is completed.");
    console.log("Proxy FastBridge Deployed at: ", proxy.address);
    console.log("FastBridge Implemenation Address: ", bridge_implementation_address);
    console.log("Proxy FastBridge Deployed by address: ", deployer.address);
    console.log("Token Address: ", tokenDeployed.address)
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
