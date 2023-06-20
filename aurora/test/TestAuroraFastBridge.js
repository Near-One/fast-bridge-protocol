require('dotenv').config();
const hre = require("hardhat");
const { execSync } = require("child_process");
const { expect } = require("chai");
const { keyStores, connect, KeyPair, Contract} = require("near-api-js");
const fs = require('fs');
const {get_unlock_proof} = require("./UnlockProof");
const {encode_init_msg_to_borsh} = require("./EncodeInitMsgToBorsh");
const borsh = require("borsh");

const WNEAR_AURORA_ADDRESS = "0x4861825E75ab14553E5aF711EbbE6873d369d146";
const NEAR_TOKEN_ADDRESS = "07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet";
const ETH_TOKEN_ADDRESS = "07865c6e87b9f70255377e024ace6630c1eaa37f";
const AURORA_TOKEN_ADDRESS="0x901fb725c106E182614105335ad0E230c91B67C8";
const ETH_CLIENT_ACCOUNT="client-eth2.goerli.testnet";

const ETH_BLOCK_TIME = 12000000000;

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
const near_fast_bridge_account_str = "fb-aurora-to-eth-test." + master_account_str;

class Assignable {
    constructor(properties) {
        Object.keys(properties).map((key) => {
            this[key] = properties[key];
        });
    }
}

class BorshStruct extends Assignable { }

async function get_last_block_number() {
    const nearConnection = await connect(connectionConfig);
    const master_account = await nearConnection.account(master_account_str);
    const eth_client_on_near_contract = await new Contract(
        master_account,
        ETH_CLIENT_ACCOUNT,
        {
            changeMethods: ["last_block_number"],
        }
    );

    const result = await
        master_account.connection.provider.query({
            request_type: 'call_function',
            finality: 'final',
            account_id: ETH_CLIENT_ACCOUNT,
            method_name: "last_block_number",
            args_base64: ''
        });

    const schema = new Map([[BorshStruct, { kind: 'struct', fields: [['x', 'u64']]}]]);
    const newValue = borsh.deserialize(schema, BorshStruct, Buffer.from(result.result));
    return Number(newValue.x);
}


async function deploy_fast_bridge() {
    const nearConnection = await connect(connectionConfig);

    let keyPair = await myKeyStore.getKey(connectionConfig.networkId, near_fast_bridge_account_str);
    if (keyPair === null) {
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
            eth_bridge_contract: "DBE11ADC5F9c821341A837f4810123f495fBFd44",
            //https://github.com/aurora-is-near/rainbow-bridge/blob/master/contracts/near/eth-prover/src/lib.rs
            //"prover.goerli.testnet" -- is a old version
            prover_account: "dev-1686914396147-58513449591656",
            eth_client_account: ETH_CLIENT_ACCOUNT,
            lock_time_min: "1s",
            lock_time_max: "24h",
            eth_block_time: 12000000000,
            whitelist_mode: true,
            start_nonce: "0",
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
}

async function deploy_aurora_fast_bridge_and_init_transfer() {
    const provider = hre.ethers.provider;
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    console.log(
        "Deploying contracts with the account:",
        deployerWallet.address
    );

    console.log(
        "Account balance:",
        (await deployerWallet.getBalance()).toString()
    );

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
    console.log("Aurora Fast Bridge Address: ", fastbridge.address);

    await sleep(15000);

    const wnear = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
    await wnear.approve(fastbridge.address, "4012500000000000000000000");

    await fastbridge.tokens_registration(AURORA_TOKEN_ADDRESS, NEAR_TOKEN_ADDRESS, options);
    console.log("Aurora Fast Bridge Address on Near: ", await fastbridge.get_near_address());
    await sleep(15000);

    const usdc = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", AURORA_TOKEN_ADDRESS);
    await usdc.approve(fastbridge.address, "2000000000000000000000000");

    let lock_period = 50000000000;
    const valid_till = Date.now() * 1000000 + lock_period;

    await sleep(15000);
    const balance_before = await usdc.balanceOf(deployerWallet.address);
    const transfer_msg_hex = encode_init_msg_to_borsh(valid_till, NEAR_TOKEN_ADDRESS, ETH_TOKEN_ADDRESS,
        100, 100, deployerWallet.address, deployerWallet.address);

    await fastbridge.init_token_transfer(transfer_msg_hex, options);

    const last_block_height = await get_last_block_number();
    const valid_till_block_height = Math.ceil((last_block_height + lock_period / ETH_BLOCK_TIME));

    await sleep(20000);
    const balance_after_init_transfer = await usdc.balanceOf(deployerWallet.address);
    expect(balance_before - balance_after_init_transfer).to.equals(200);

    await fastbridge.withdraw(NEAR_TOKEN_ADDRESS, options);
    await sleep(20000);
    const balance_after_withdraw = await usdc.balanceOf(deployerWallet.address);
    expect(balance_after_init_transfer).to.equals(balance_after_withdraw);

    return [fastbridge.address, valid_till_block_height, balance_before];
}

async function aurora_unlock_tokens(aurora_fast_bridge_address, valid_till_block_height, balance_before) {
    const provider = hre.ethers.provider;
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);
    const AuroraErc20FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": process.env.AURORA_SDK_ADDRESS,
            "Utils": process.env.AURORA_UTILS_ADDRESS
        },
    });

    const fastbridge = await AuroraErc20FastBridge.attach(aurora_fast_bridge_address);

    const { get_unlock_proof } = require('./UnlockProof');
    const proof = await get_unlock_proof("0xDBE11ADC5F9c821341A837f4810123f495fBFd44",
        { token: "0x" + ETH_TOKEN_ADDRESS,
            recipient: deployerWallet.address,
            nonce: 1,
            amount: 100}, valid_till_block_height);

    console.log("proof: ",  proof);
    console.log("proof len: ", proof.length);

    const options = { gasLimit: 6000000 };
    console.log("Unlock");
    await fastbridge.unlock(1, proof, options);
    await sleep(15000);

    console.log("Withdraw from near");
    await fastbridge.withdraw_from_near(NEAR_TOKEN_ADDRESS, 200, options);
    await sleep(15000);

    console.log("Withdraw");
    await fastbridge.withdraw(NEAR_TOKEN_ADDRESS, options);
    await sleep(150000);
    const usdc = await hre.ethers.getContractAt("openzeppelin-contracts/token/ERC20/IERC20.sol:IERC20", AURORA_TOKEN_ADDRESS);
    const balance_after_unlock = await usdc.balanceOf(deployerWallet.address);
    expect(balance_before).to.equals(balance_after_unlock);
}

async function wait_for_block_height(block_height) {
    let current_block_number = await get_last_block_number();
    while (current_block_number < block_height) {
        current_block_number = await get_last_block_number();
        console.log("Current block number = ", current_block_number, "; wait for = ",block_height);
        await sleep(10000);
    }
}

describe("Aurora Fast Bridge", function () {
    it("The Basic Aurora->Eth transfer with unlock", async function () {
        await deploy_fast_bridge();
        console.log("Near fast bridge account: " + near_fast_bridge_account_str);

        let [aurora_fast_bridge_address, valid_till_block_height, balance_before] = await deploy_aurora_fast_bridge_and_init_transfer();
        console.log("Valid till block height: ", valid_till_block_height);

        await wait_for_block_height(valid_till_block_height);

        await aurora_unlock_tokens(aurora_fast_bridge_address, valid_till_block_height, balance_before);
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