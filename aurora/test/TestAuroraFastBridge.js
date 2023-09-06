require('dotenv').config();
const hre = require("hardhat");
const { execSync } = require("child_process");
const { expect } = require("chai");
const { keyStores, connect, KeyPair, Contract} = require("near-api-js");
const fs = require('fs');
const {getUnlockProof} = require("./UnlockProof");
const {encodeInitMsgToBorsh} = require("./EncodeInitMsgToBorsh");
const borsh = require("borsh");

const WNEAR_AURORA_ADDRESS = "0x4861825E75ab14553E5aF711EbbE6873d369d146";
const NEAR_TOKEN_ACCOUNT_ID = "07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet";
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

const masterAccountStr = process.env.MASTER_ACCOUNT;
const nearFastBridgeAccountStr = "fb-aurora-to-eth-test." + masterAccountStr;

class Assignable {
    constructor(properties) {
        Object.keys(properties).map((key) => {
            this[key] = properties[key];
        });
    }
}

class BorshStruct extends Assignable { }

async function getLastBlockNumberOnNear() {
    const nearConnection = await connect(connectionConfig);
    const masterAccount = await nearConnection.account(masterAccountStr);

    const result = await
        masterAccount.connection.provider.query({
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


async function deployFastBridgeOnNear() {
    const nearConnection = await connect(connectionConfig);

    let keyPair = await myKeyStore.getKey(connectionConfig.networkId, nearFastBridgeAccountStr);
    if (keyPair === null) {
        keyPair = KeyPair.fromRandom("ed25519");
        await myKeyStore.setKey(connectionConfig.networkId, nearFastBridgeAccountStr, keyPair);
    }
    const publicKey = keyPair.publicKey.toString();

    const master_account = await nearConnection.account(masterAccountStr);
    await master_account.createAccount(
        nearFastBridgeAccountStr,
        publicKey,
        "20000000000000000000000000"
    )
    const nearFastBridgeAccount = await nearConnection.account(nearFastBridgeAccountStr);
    await nearFastBridgeAccount.deployContract(fs.readFileSync("../near/res/fastbridge.wasm"));

    const nearFastBridgeContract = new Contract(
        nearFastBridgeAccount,
        nearFastBridgeAccountStr,
        {
            changeMethods: ["new", "acl_grant_role", "set_token_whitelist_mode"],
        }
    );

    await nearFastBridgeContract.new({args: {
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

    await nearFastBridgeContract.acl_grant_role({
        args: {
            account_id: nearFastBridgeAccountStr,
            role: "WhitelistManager"
        }
    });

    await nearFastBridgeContract.set_token_whitelist_mode({
        args: {
            token: NEAR_TOKEN_ACCOUNT_ID,
            mode: "CheckToken"
        }
    });

    const nearTokenContract = new Contract(
        master_account,
        NEAR_TOKEN_ACCOUNT_ID,
        {
            changeMethods: ["storage_deposit"],
        }
    );

    await nearTokenContract.storage_deposit({
        args: {
            account_id: nearFastBridgeAccountStr
        },
        amount: "12500000000000000000000",
    });
}

async function deployAuroraFastBridgeAndInitTransfer(config) {
    const provider = hre.ethers.getDefaultProvider("https://testnet.aurora.dev");
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);

    console.log(
        "Deploying contracts with the account:",
        deployerWallet.address
    );

    const AuroraErc20FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": config.auroraSdkAddress,
            "Utils": config.auroraUtilsAddress
        },
    });
    const options = { gasLimit: 6000000 };
    const fastbridge = await AuroraErc20FastBridge.connect(deployerWallet);
    let proxy = await hre.upgrades.deployProxy(fastbridge, [WNEAR_AURORA_ADDRESS, nearFastBridgeAccountStr, "aurora", true], {
        initializer: "initialize",
        unsafeAllowLinkedLibraries: true,
    });

    await proxy.waitForDeployment();
    console.log("Aurora Fast Bridge Address: ", await proxy.getAddress());

    await sleep(15000);

    const wnear = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", WNEAR_AURORA_ADDRESS);
    await wnear.approve(await proxy.getAddress(), "4012500000000000000000000");

    console.log("Blanace of wNEAR of signer: ", await wnear.balanceOf(deployerWallet.address));

    await proxy.registerToken(NEAR_TOKEN_ACCOUNT_ID, options);
    await proxy.storageDeposit(NEAR_TOKEN_ACCOUNT_ID, "12500000000000000000000", options);
    console.log("Aurora Fast Bridge Account Id on Near: ", await proxy.getImplicitNearAccountIdForSelf());
    await sleep(15000);

    const usdc = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", AURORA_TOKEN_ADDRESS);
    await usdc.approve(await proxy.getAddress(), "2000000000000000000000000");

    let lockPeriod = 50000000000;
    const validTill = Date.now() * 1000000 + lockPeriod;

    await sleep(15000);
    const balanceBefore = await usdc.balanceOf(deployerWallet.address);
    const transferMsgHex = encodeInitMsgToBorsh(validTill, NEAR_TOKEN_ACCOUNT_ID, ETH_TOKEN_ADDRESS,
        100, 100, deployerWallet.address, deployerWallet.address);

    await proxy.initTokenTransfer(transferMsgHex, options);

    const lastBlockHeight = await getLastBlockNumberOnNear();
    const validTillBlockHeight = Math.ceil((lastBlockHeight + lockPeriod / ETH_BLOCK_TIME));

    await sleep(20000);
    const balanceAfterInitTransfer = await usdc.balanceOf(deployerWallet.address);
    expect(balanceBefore - balanceAfterInitTransfer).to.equals(200);

    await proxy.withdrawFromImplicitNearAccount(NEAR_TOKEN_ACCOUNT_ID, options);
    await sleep(20000);
    const balanceAfterWithdraw = await usdc.balanceOf(deployerWallet.address);
    expect(balanceAfterInitTransfer).to.equals(balanceAfterWithdraw);

    return [await proxy.getAddress(), validTillBlockHeight, balanceBefore];
}

async function auroraUnlockTokens(auroraFastBridgeAddress, validTillBlockHeight, balanceBefore, config) {
    const provider = hre.ethers.provider;
    const deployerWallet = new hre.ethers.Wallet(process.env.AURORA_PRIVATE_KEY, provider);
    const AuroraErc20FastBridge = await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": config.auroraSdkAddress,
            "Utils": config.auroraUtilsAddress
        },
    });

    const fastbridge = await AuroraErc20FastBridge.attach(auroraFastBridgeAddress);

    const { getUnlockProof } = require('./UnlockProof');
    const proof = await getUnlockProof("0xDBE11ADC5F9c821341A837f4810123f495fBFd44",
        { token: "0x" + ETH_TOKEN_ADDRESS,
            recipient: deployerWallet.address,
            nonce: 1,
            amount: 100}, validTillBlockHeight);

    console.log("proof: ",  proof);
    console.log("proof len: ", proof.length);

    const options = { gasLimit: 6000000 };
    console.log("Unlock");
    await fastbridge.unlock(1, proof, options);
    await sleep(15000);

    console.log("Fast Bridge Withdraw on Near");
    await fastbridge.fastBridgeWithdrawOnNear(NEAR_TOKEN_ACCOUNT_ID, 200, options);
    await sleep(15000);

    console.log("Withdraw from implicit Near account");
    await fastbridge.withdrawFromImplicitNearAccount(NEAR_TOKEN_ACCOUNT_ID, options);
    await sleep(150000);
    const usdc = await hre.ethers.getContractAt("@openzeppelin/contracts/token/ERC20/IERC20.sol:IERC20", AURORA_TOKEN_ADDRESS);
    const balanceAfterUnlock = await usdc.balanceOf(deployerWallet.address);
    expect(balanceBefore).to.equals(balanceAfterUnlock);
}

async function waitForBlockHeight(blockHeight) {
    let currentBlockNumber = await getLastBlockNumberOnNear();
    while (currentBlockNumber < blockHeight) {
        currentBlockNumber = await getLastBlockNumberOnNear();
        console.log("Current block number = ", currentBlockNumber, "; wait for = ", blockHeight);
        await sleep(10000);
    }
}

describe("Aurora Fast Bridge", function () {
    it("The Basic Aurora->Eth transfer with unlock", async function () {
        const config = require(`../configs/aurora-testnet.json`);

        await deployFastBridgeOnNear();
        console.log("Near fast bridge account: " + nearFastBridgeAccountStr);

        let [auroraFastBridgeAddress, validTillBlockHeight, balanceBefore] =
            await deployAuroraFastBridgeAndInitTransfer(config);
        console.log("Valid till block height: ", validTillBlockHeight);

        await waitForBlockHeight(validTillBlockHeight);

        await auroraUnlockTokens(auroraFastBridgeAddress, validTillBlockHeight, balanceBefore, config);
    });

    afterEach(async function() {
        const nearConnection = await connect(connectionConfig);

        const nearFastBridgeAccount = await nearConnection.account(nearFastBridgeAccountStr);
        await nearFastBridgeAccount.deleteAccount(masterAccountStr);
    });
});

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}