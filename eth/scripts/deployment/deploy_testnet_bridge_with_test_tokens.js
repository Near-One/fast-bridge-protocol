const { ethers } = require("hardhat");
const {deployBridge} = require("./deploy-bridge");
const {deployTestToken} = require("./deploy-test-tokens");

const main = async () => {
    const chainID = (await ethers.provider.getNetwork()).chainId;
    if (chainID == 1){
        console.log("deploying test tokens only available for testnets!!!");
        return;
    }
    console.log("deploying test tokens");
    await deployTestToken();
    console.log("deploying bridge with tokens whitelisted");
    await deployBridge();
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});