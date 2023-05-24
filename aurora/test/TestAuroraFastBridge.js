require('dotenv').config();
const hre = require("hardhat");
const { execSync } = require("child_process");
const { expect } = require("chai");
const { keyStores, connect, KeyPair, Contract} = require("near-api-js");
const fs = require('fs');

const WNEAR_AURORA_ADDRESS = "0x4861825E75ab14553E5aF711EbbE6873d369d146";
const NEAR_TOKEN_ADDRESS = "07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet"
const ETH_TOKEN_ADDRESS = "07865c6e87b9f70255377e024ace6630c1eaa37f";
const AURORA_TOKEN_ADDRESS="0x901fb725c106E182614105335ad0E230c91B67C8"

const homedir = require("os").homedir();
const CREDENTIALS_DIR = ".near-credentials";
const credentialsPath = require("path").join(homedir, CREDENTIALS_DIR);
const myKeyStore = new keyStores.UnencryptedFileSystemKeyStore(credentialsPath);

const connectionConfig = {
    networkId: "testnet",
    keyStore: myKeyStore, // first create a key store
    nodeUrl: "https://rpc.testnet.near.org",
    walletUrl: "https://wallet.testnet.near.org",
    helperUrl: "https://helper.testnet.near.org",
    explorerUrl: "https://explorer.testnet.near.org",
};

const master_account_str = process.env.MASTER_ACCOUNT;
const near_fast_bridge_account_str = "fb-test8." + master_account_str;

describe("Aurora Fast Bridge", function () {
    it("The Basic Aurora->Eth transfer with unlock", async function () {
        const nearConnection = await connect(connectionConfig);

        let keyPair = await myKeyStore.getKey(connectionConfig.networkId, near_fast_bridge_account_str);
        if (keyPair === undefined) {
            keyPair = KeyPair.fromRandom("ed25519");
            await myKeyStore.setKey(connectionConfig.networkId, near_fast_bridge_account_str, keyPair);
        }
        const publicKey = keyPair.publicKey.toString();

        const master_account = await nearConnection.account(master_account_str);
        await master_account.createAccount(
            near_fast_bridge_account_str,
            publicKey,
            "20000000000000000000000000"
        )
        const near_fast_bridge_account = await nearConnection.account(near_fast_bridge_account_str);
        await near_fast_bridge_account.deployContract(fs.readFileSync("../near/res/fastbridge.wasm"));

        const near_fast_bridge_contract = new Contract(
            near_fast_bridge_account,
            near_fast_bridge_account_str,
            {
                changeMethods: ["new", "acl_grant_role", "set_token_whitelist_mode"],
            }
        );

        await near_fast_bridge_contract.new({args: {
            eth_bridge_contract: "8AC4c4A1015A9A12A9DBA16234A3f7909b9396Eb",
            prover_account: "prover.goerli.testnet",
            eth_client_account: "client-eth2.goerli.testnet",
            lock_time_min: "1s",
            lock_time_max: "24h",
            eth_block_time: 12000000000
        }, gas: "300000000000000"});

        await near_fast_bridge_contract.acl_grant_role({
            args: {
                account_id: near_fast_bridge_account_str,
                role: "WhitelistManager"
            }
        });

        await near_fast_bridge_contract.set_token_whitelist_mode({
            args: {
                token: NEAR_TOKEN_ADDRESS,
                mode: "CheckToken"
            }
        });

        const near_token_contract = new Contract(
            master_account,
            NEAR_TOKEN_ADDRESS,
            {
                changeMethods: ["storage_deposit"],
            }
        );

        await near_token_contract.storage_deposit({
            args: {
                account_id: near_fast_bridge_account_str
            },
            amount: "12500000000000000000000",
        });

        console.log("Near fast bridge account: " + near_fast_bridge_account_str);

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
            .deploy(WNEAR_AURORA_ADDRESS, near_fast_bridge_account_str, options);
        await fastbridge.deployed();
        await sleep(15000);

        const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
        await wnear.approve(fastbridge.address, "4012500000000000000000000");

        await fastbridge.tokens_registration(AURORA_TOKEN_ADDRESS, NEAR_TOKEN_ADDRESS, options);
        console.log("Aurora Fast Bridge Address on Near: ", await fastbridge.get_near_address());
        await sleep(15000);

        const usdc = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", AURORA_TOKEN_ADDRESS);
        await usdc.approve(fastbridge.address, "2000000000000000000000000");

        const valid_till = Date.now() * 1000000 + 10000000000;
        const transfer_msg_json = "{\"valid_till\":" + valid_till + ",\"transfer\":{\"token_near\":\"" + NEAR_TOKEN_ADDRESS + "\",\"token_eth\":\"" + ETH_TOKEN_ADDRESS + "\",\"amount\":\"100\"},\"fee\":{\"token\":\"" + NEAR_TOKEN_ADDRESS + "\",\"amount\":\"100\"},\"recipient\":\"" + deployerWallet.address + "\",\"valid_till_block_height\":null,\"aurora_sender\":\"" + deployerWallet.address + "\"}";
        const output = execSync('cargo run --manifest-path ../near/utils/Cargo.toml -- encode-transfer-msg -m \'' + transfer_msg_json + '\'', { encoding: 'utf-8' });  // the default is 'buffer'

        await sleep(15000);
        const balance_before = await usdc.balanceOf(deployerWallet.address);
        const transfer_msg_hex = "0x" + output.split(/\r?\n/)[1].slice(1, -1);
        await fastbridge.init_token_transfer(transfer_msg_hex, options);

        await sleep(20000);
        const balance_after_init_transfer = await usdc.balanceOf(deployerWallet.address);
        expect(balance_before - balance_after_init_transfer).to.equals(200);

        await sleep(100000);

        await fastbridge.unlock(1, options);
        await sleep(15000);
        await fastbridge.withdraw_from_near(NEAR_TOKEN_ADDRESS, 200, options);
        await sleep(15000);
        await fastbridge.withdraw(NEAR_TOKEN_ADDRESS, options);
        await sleep(150000);
        const balance_after_unlock = await usdc.balanceOf(deployerWallet.address);
        expect(balance_before).to.equals(balance_after_unlock);
    });

    afterEach(async function() {
        const nearConnection = await connect(connectionConfig);

        const near_fast_bridge_account = await nearConnection.account(near_fast_bridge_account_str);
        await near_fast_bridge_account.deleteAccount(master_account_str);
    });
});

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}