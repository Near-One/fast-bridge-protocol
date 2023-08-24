require("@nomicfoundation/hardhat-chai-matchers");
require("@openzeppelin/hardhat-upgrades");
// Replace this private key with your Ropsten account private key
// To export your private key from Metamask, open Metamask and
// go to Account Details > Export Private Key
// Be aware of NEVER putting real Ether into testing accounts
require('dotenv').config();

const AURORA_PRIVATE_KEY = process.env.AURORA_PRIVATE_KEY;

task("deploy", "Deploy aurora fast bridge proxy contract")
    .addParam("silo", "Config file name without extension")
    .setAction(async (taskArgs, hre) => {
        const { deploy } = require("./scripts/deploy.js");
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await hre.run("compile");
        await deploy({
            signer,
            nearFastBridgeAccount: config.nearFastBridgeAccount,
            auroraEngineAccountId: config.auroraEngineAccountId,
            wNearAddress: config.wNearAddress,
            auroraSdkAddress: config.auroraSdkAddress,
            auroraUtilsAddress: config.auroraUtilsAddress
        });
    });

task("upgrade", "Upgrade aurora fast bridge proxy contract")
    .addParam("silo", "Config file name without extension")
    .addParam("proxy", "Current proxy address of the AuroraErc20FastBridge contract")
    .setAction(async (taskArgs, hre) => {
        const { upgrade } = require("./scripts/deploy.js");
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await hre.run("compile");
        await upgrade({
            signer,
            proxyAddress: taskArgs.proxy,
            auroraSdkAddress: config.auroraSdkAddress,
            auroraUtilsAddress: config.auroraUtilsAddress
        });
    });

task('tokens_registration', 'Register tokens and storage deposit on NEAR for the contract')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAddress', "Token address on Near")
    .addParam('auroraTokenAddress', "Token address on Aurora")
    .setAction(async taskArgs => {
        const { tokensRegistration } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await tokensRegistration(signer, config, taskArgs.fastBridgeAddress, taskArgs.nearTokenAddress, taskArgs.auroraTokenAddress);
    });

task('init_token_transfer', 'Initialize Token Transfer from Aurora to Ethereum')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAddress', "Token address on Near")
    .addParam('auroraTokenAddress', "Token address on Aurora")
    .addParam('ethTokenAddress', "Token address on Eth")
    .setAction(async taskArgs => {
        const { initTokenTransfer } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await initTokenTransfer(signer, config, taskArgs.fastBridgeAddress, taskArgs.nearTokenAddress, taskArgs.auroraTokenAddress, taskArgs.ethTokenAddress);
    });

task('unlock', 'Unlock tokens on Near')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nonce', 'nonce')
    .setAction(async taskArgs => {
        const { unlock } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await unlock(signer, config, taskArgs.fastBridgeAddress, taskArgs.nonce);
    });

task('withdraw_from_near', 'Withdraw tokens on Near side')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAddress', "Token address on Near")
    .addParam('tokenAmount', "Withdraw tokens amount")
    .setAction(async taskArgs => {
        const { withdraw_from_near } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await withdraw_from_near(signer, config, taskArgs.fastBridgeAddress, taskArgs.nearTokenAddress, taskArgs.tokenAmount);
    });

task('withdraw', 'Withdraw tokens to user on Aurora')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAddress', "Token address on Near")
    .setAction(async taskArgs => {
        const { withdraw } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await withdraw(signer, config, taskArgs.fastBridgeAddress, taskArgs.nearTokenAddress);
    });

task('get_near_account_id', '')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .setAction(async taskArgs => {
        const { get_near_account_id } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await get_near_account_id(signer, config, taskArgs.fastBridgeAddress);
    });
    
task('get_token_aurora_address', '')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAddress', "Token address on Near")
    .setAction(async taskArgs => {
        const { get_token_aurora_address } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await get_token_aurora_address(signer, config, taskArgs.fastBridgeAddress, taskArgs.nearTokenAddress);
    });

module.exports = {
    solidity: {
        version: "0.8.17",
        settings: {
            optimizer: {
                enabled: true,
                runs: 200
            }
        }
    },
    networks: {
        testnet_aurora: {
            url: 'https://testnet.aurora.dev',
            accounts: [`0x${AURORA_PRIVATE_KEY}`],
            chainId: 1313161555,
            timeout: 100_000_000_000
        },
        develop_aurora: {
            url: 'https://develop.rpc.testnet.aurora.dev:8545',
            accounts: [`0x${AURORA_PRIVATE_KEY}`]
        },
        ropsten: {
            url: 'https://rpc.testnet.aurora.dev:8545',
            accounts: [`0x${AURORA_PRIVATE_KEY}`]
        }
    },
    mocha: {
        timeout: 1000000000000
    }
};
