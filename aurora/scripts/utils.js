require('dotenv').config();
const hre = require("hardhat");

async function initNearContract(provider, fastBridgeAddress) {
    fastBridgeAddress = hre.ethers.utils.getAddress(fastBridgeAddress);
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    console.log("Sending transaction with the account:", deployerWallet.address);
    console.log("Account balance:", (await deployerWallet.getBalance()).toString());

    const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", "0x4861825E75ab14553E5aF711EbbE6873d369d146");
    await wnear.approve(fastBridgeAddress, "2000000000000000000000000");

    const FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": "0x425cA8f218784ebE2df347E98c626094B63E7f30",
        },
    });
    const fast_bridge = await FastBridge
        .attach(fastBridgeAddress)
        .connect(deployerWallet);

    let tx = await fast_bridge.init_near_contract();
    let receipt = await tx.wait();

    console.log("Aurora Fast Bridge Address on Near: ", receipt.events[0].args);
}

exports.initNearContract = initNearContract;
