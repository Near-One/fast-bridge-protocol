require("@nomicfoundation/hardhat-chai-matchers");
require("@openzeppelin/hardhat-upgrades");
// Replace this private key with your Ropsten account private key
// To export your private key from Metamask, open Metamask and
// go to Account Details > Export Private Key
// Be aware of NEVER putting real Ether into testing accounts
require('dotenv').config();

const AURORA_PRIVATE_KEY = process.env.AURORA_PRIVATE_KEY;

task('tokens_registration', 'Register tokens and storage deposit on NEAR for the contract')
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAddress', "Token address on Near")
    .addParam('auroraTokenAddress', "Token address on Aurora")
    .setAction(async taskArgs => {
        const { tokensRegistration } = require('./scripts/utils');
        await tokensRegistration(hre.ethers.provider, taskArgs.fastBridgeAddress, taskArgs.nearTokenAddress, taskArgs.auroraTokenAddress);
    });

task('init_token_transfer', 'Initialize Token Transfer from Aurora to Ethereum')
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('initTokenTransferArg', 'argument for token transfer initialization')
    .addParam('auroraTokenAddress', "Token address on Aurora")
    .setAction(async taskArgs => {
        const { initTokenTransfer } = require('./scripts/utils');
        await initTokenTransfer(hre.ethers.provider, taskArgs.fastBridgeAddress, taskArgs.initTokenTransferArg, taskArgs.auroraTokenAddress);
    });

task('unlock', 'Unlock tokens on Near')
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nonce', 'nonce')
    .setAction(async taskArgs => {
        const { unlock } = require('./scripts/utils');
        await unlock(hre.ethers.provider, taskArgs.fastBridgeAddress, taskArgs.nonce);
    });

task('withdraw_from_near', 'Withdraw tokens on Near side')
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAddress', "Token address on Near")
    .addParam('tokenAmount', "Withdraw tokens amount")
    .setAction(async taskArgs => {
        const { withdraw_from_near } = require('./scripts/utils');
        await withdraw_from_near(hre.ethers.provider, taskArgs.fastBridgeAddress, taskArgs.nearTokenAddress, taskArgs.tokenAmount);
    });

task('withdraw', 'Withdraw tokens to user on Aurora')
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAddress', "Token address on Near")
    .setAction(async taskArgs => {
        const { withdraw } = require('./scripts/utils');
        await withdraw(hre.ethers.provider, taskArgs.fastBridgeAddress, taskArgs.nearTokenAddress);
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

