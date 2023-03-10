require('dotenv').config();
const hre = require("hardhat");

const WNEAR_AURORA_ADDRESS = "0x4861825E75ab14553E5aF711EbbE6873d369d146";
const NEAR_TOKEN_ADDRESS="07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet"
const AURORA_TOKEN_ADDRESS="0x901fb725c106E182614105335ad0E230c91B67C8"

describe("Aurora Fast Bridge", function () {
    it("Deploy test", async function () {
        const provider = hre.ethers.provider;
        const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);
        const AuroraErc20FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
            libraries: {
                "AuroraSdk": "0x425cA8f218784ebE2df347E98c626094B63E7f30",
                "Utils": "0xc129336a6995F3b70A7139585403B82098260172"
            },
        });
        const options = { gasLimit: 6000000 };
        const fastbridge = await AuroraErc20FastBridge.connect(deployerWallet)
            .deploy("0x4861825E75ab14553E5aF711EbbE6873d369d146", "fb.olga24912_3.testnet", options);
        await fastbridge.deployed();

        const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
        await wnear.approve(fastbridge.address, "4012500000000000000000000");

        await fastbridge.tokens_registration(AURORA_TOKEN_ADDRESS, NEAR_TOKEN_ADDRESS);
        console.log("Aurora Fast Bridge Address on Near: ", await fastbridge.get_near_address());

        const usdc = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", AURORA_TOKEN_ADDRESS);
        await usdc.approve(fastbridge.address, "2000000000000000000000000");

        const valid_till = Date.now() * 1000000 + 120000000000;
        const transfer_msg_json = "{\"valid_till\":" + valid_till + ",\"transfer\":{\"token_near\":\"07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet\",\"token_eth\":\"07865c6e87b9f70255377e024ace6630c1eaa37f\",\"amount\":\"100000\"},\"fee\":{\"token\":\"07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet\",\"amount\":\"100000\"},\"recipient\":\"1c6a38ac14e5fdd4f378192fad90db7025f1db67\",\"valid_till_block_height\":null,\"aurora_sender\":\"1c6a38ac14e5fdd4f378192fad90db7025f1db67\"}";

        const execSync = require('child_process').execSync;
        const output = execSync('cargo run --manifest-path ../near/utils/Cargo.toml -- encode-transfer-msg -m \'' + transfer_msg_json + '\'', { encoding: 'utf-8' });  // the default is 'buffer'

        const transfer_msg_hex = "0x" + output.split(/\r?\n/)[1].slice(1, -1);
        await fastbridge.init_token_transfer(transfer_msg_hex);

        await sleep(150000);

        await fastbridge.unlock(27);
        await fastbridge.withdraw_from_near(NEAR_TOKEN_ADDRESS, 200000);
        await fastbridge.withdraw(NEAR_TOKEN_ADDRESS);
    });
});

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}