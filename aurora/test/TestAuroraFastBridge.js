require('dotenv').config();
const hre = require("hardhat");

describe("Aurora Fast Bridge", function () {
    it("Deploy test", async function () {
        const provider = hre.ethers.provider;
        const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);
        const AuroraErc20FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
            libraries: {
                "AuroraSdk": "0x425cA8f218784ebE2df347E98c626094B63E7f30",
            },
        });
        const options = { gasLimit: 5000000 };
        const fastbridge = await AuroraErc20FastBridge.connect(deployerWallet)
            .deploy("0x4861825E75ab14553E5aF711EbbE6873d369d146", process.env.NEAR_FAST_BRIDGE_ACCOUNT, options);
        await fastbridge.deployed();
    });
});