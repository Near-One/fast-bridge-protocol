require('dotenv').config();
const hre = require("hardhat");

async function tokensRegistration(provider, fastBridgeAddress) {
    fastBridgeAddress = hre.ethers.utils.getAddress(fastBridgeAddress);
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    console.log("Sending transaction with the account:", deployerWallet.address);
    console.log("Account balance:", (await deployerWallet.getBalance()).toString());

    const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", "0x4861825E75ab14553E5aF711EbbE6873d369d146");
    await wnear.approve(fastBridgeAddress, "4012500000000000000000000");

    const FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": "0x425cA8f218784ebE2df347E98c626094B63E7f30",
        },
    });
    const fast_bridge = await FastBridge
        .attach(fastBridgeAddress)
        .connect(deployerWallet);

    let tx = await fast_bridge.tokens_registration("0x901fb725c106E182614105335ad0E230c91B67C8", "07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet");
    let receipt = await tx.wait();

    console.log("Aurora Fast Bridge Address on Near: ", receipt.events[0].args);
}

async function initTokenTransfer(provider, fastBridgeAddress) {
    fastBridgeAddress = hre.ethers.utils.getAddress(fastBridgeAddress);
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    console.log("Sending transaction with the account:", deployerWallet.address);
    console.log("Account balance:", (await deployerWallet.getBalance()).toString());

    const usdc = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", "0x901fb725c106E182614105335ad0E230c91B67C8");
    await usdc.approve(fastBridgeAddress, "2000000000000000000000000");

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

    let tx = await fast_bridge.init_token_transfer("0xc5b125d33b0e48173f000000303738363563366538376239663730323535333737653032346163653636333063316561613337662e666163746f72792e676f65726c692e746573746e657407865c6e87b9f70255377e024ace6630c1eaa37fa08601000000000000000000000000003f000000303738363563366538376239663730323535333737653032346163653636333063316561613337662e666163746f72792e676f65726c692e746573746e6574a08601000000000000000000000000001c6a38ac14e5fdd4f378192fad90db7025f1db6700");
    let receipt = await tx.wait();
    console.log(receipt.events[0].args);
}

async function withdraw(provider, fastBridgeAddress) {
    fastBridgeAddress = hre.ethers.utils.getAddress(fastBridgeAddress);
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

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

    let tx = await fast_bridge.withdraw("07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet");
    let receipt = await tx.wait();
}

exports.initTokenTransfer = initTokenTransfer;
exports.tokensRegistration = tokensRegistration;
exports.withdraw = withdraw;