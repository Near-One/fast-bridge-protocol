require('dotenv').config();
const hre = require("hardhat");
const { execSync } = require("child_process");
const { expect } = require("chai");

const WNEAR_AURORA_ADDRESS = "0x4861825E75ab14553E5aF711EbbE6873d369d146";
const NEAR_TOKEN_ADDRESS = "07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet"
const ETH_TOKEN_ADDRESS = "07865c6e87b9f70255377e024ace6630c1eaa37f";
const AURORA_TOKEN_ADDRESS="0x901fb725c106E182614105335ad0E230c91B67C8"

describe("Aurora Fast Bridge", function () {
    it("The Basic Aurora->Eth transfer with unlock", async function () {
        const master_account = process.env.MASTER_ACCOUNT;
        const near_fast_bridge_account = "fb-test." + master_account;

        execSync("near create-account " + near_fast_bridge_account + " --masterAccount "+ master_account + " --initialBalance 20")
        execSync("near deploy " + near_fast_bridge_account + " --wasmFile ../near/res/fastbridge.wasm --initGas   300000000000000 --initFunction 'new' --initArgs '{\"eth_bridge_contract\": \"8AC4c4A1015A9A12A9DBA16234A3f7909b9396Eb\", \"prover_account\": \"prover.goerli.testnet\", \"eth_client_account\": \"client-eth2.goerli.testnet\", \"lock_time_min\": \"1s\", \"lock_time_max\": \"24h\", \"eth_block_time\": 12000000000}'", { encoding: 'utf-8' });
        execSync("near call " + NEAR_TOKEN_ADDRESS + " storage_deposit --args '{\"account_id\": \"" + near_fast_bridge_account + "\"}' --amount 0.0125 --accountId " + master_account);
        execSync("near call " + near_fast_bridge_account + " acl_grant_role '{\"account_id\": \"" + master_account + "\", \"role\": \"WhitelistManager\"}' --accountId " + near_fast_bridge_account);
        execSync("near call " + near_fast_bridge_account + " set_token_whitelist_mode '{\"token\": \"" + NEAR_TOKEN_ADDRESS + "\", \"mode\": \"CheckToken\"}' --accountId " + master_account);
        console.log("Near fast bridge account: " + near_fast_bridge_account);

        const provider = hre.ethers.provider;
        const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);
        const AuroraErc20FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
            libraries: {
                "AuroraSdk": process.env.AURORA_SDK_ADDRESS,
                "Utils": process.env.AURORA_UTILS_ADDRESS
            },
        });
        const options = { gasLimit: 6000000 };
        const fastbridge = await AuroraErc20FastBridge.connect(deployerWallet)
            .deploy(WNEAR_AURORA_ADDRESS, near_fast_bridge_account, options);
        await fastbridge.deployed();
        await sleep(15000);

        const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
        await wnear.approve(fastbridge.address, "4012500000000000000000000");

        await fastbridge.tokens_registration(AURORA_TOKEN_ADDRESS, NEAR_TOKEN_ADDRESS, options);
        console.log("Aurora Fast Bridge Address on Near: ", await fastbridge.get_near_address());
        await sleep(15000);

        const usdc = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", AURORA_TOKEN_ADDRESS);
        await usdc.approve(fastbridge.address, "2000000000000000000000000");

        const valid_till = Date.now() * 1000000 + 120000000000;
        const transfer_msg_json = "{\"valid_till\":" + valid_till + ",\"transfer\":{\"token_near\":\"" + NEAR_TOKEN_ADDRESS + "\",\"token_eth\":\"" + ETH_TOKEN_ADDRESS + "\",\"amount\":\"10000\"},\"fee\":{\"token\":\"" + NEAR_TOKEN_ADDRESS + "\",\"amount\":\"10000\"},\"recipient\":\"" + deployerWallet.address + "\",\"valid_till_block_height\":null,\"aurora_sender\":\"" + deployerWallet.address + "\"}";
        const output = execSync('cargo run --manifest-path ../near/utils/Cargo.toml -- encode-transfer-msg -m \'' + transfer_msg_json + '\'', { encoding: 'utf-8' });  // the default is 'buffer'

        await sleep(15000);
        const balance_before = await usdc.balanceOf(deployerWallet.address);
        const transfer_msg_hex = "0x" + output.split(/\r?\n/)[1].slice(1, -1);
        await fastbridge.init_token_transfer(transfer_msg_hex, options);

        await sleep(20000);
        const balance_after_init_transfer = await usdc.balanceOf(deployerWallet.address);
        expect(balance_before - balance_after_init_transfer).to.equals(20000);

        await sleep(500000);

        await fastbridge.unlock(1, options);
        await sleep(15000);
        await fastbridge.withdraw_from_near(NEAR_TOKEN_ADDRESS, 20000, options);
        await sleep(15000);
        await fastbridge.withdraw(NEAR_TOKEN_ADDRESS, options);
        await sleep(150000);
        const balance_after_unlock = await usdc.balanceOf(deployerWallet.address);
        expect(balance_before).to.equals(balance_after_unlock);
    });

    afterEach(async function() {
        const master_account = process.env.MASTER_ACCOUNT;
        const near_fast_bridge_account = "fb-test." + master_account;

        execSync("near delete " + near_fast_bridge_account + " " + master_account, { encoding: 'utf-8', stdio: [process.stdin, process.stdout, 'pipe']});
    });
});

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}