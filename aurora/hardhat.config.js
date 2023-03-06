require("@nomiclabs/hardhat-waffle");
// Replace this private key with your Ropsten account private key
// To export your private key from Metamask, open Metamask and
// go to Account Details > Export Private Key
// Be aware of NEVER putting real Ether into testing accounts
require('dotenv').config();

const AURORA_PRIVATE_KEY = process.env.AURORA_PRIVATE_KEY;

task('tokens_registration', 'Init the Aurora Fast Bridge Contract on NEAR')
    .addParam('fastBridgeAddress', 'Eth address of Aurora Fast Bridge')
    .setAction(async taskArgs => {
        const { tokensRegistration } = require('./scripts/utils');
        await tokensRegistration(hre.ethers.provider, taskArgs.fastBridgeAddress);
    });

task('withdraw', 'Init the Aurora Fast Bridge Contract on NEAR')
    .addParam('fastBridgeAddress', 'Eth address of Aurora Fast Bridge')
    .setAction(async taskArgs => {
        const { withdraw } = require('./scripts/utils');
        await withdraw(hre.ethers.provider, taskArgs.fastBridgeAddress);
    });

task('withdraw_from_near', 'Init the Aurora Fast Bridge Contract on NEAR')
    .addParam('fastBridgeAddress', 'Eth address of Aurora Fast Bridge')
    .setAction(async taskArgs => {
        const { withdraw_from_near } = require('./scripts/utils');
        await withdraw_from_near(hre.ethers.provider, taskArgs.fastBridgeAddress);
    });

task('init_token_transfer', 'Init Token Transfer from Aurora to Eth')
    .addParam('fastBridgeAddress', 'Eth address of Aurora Fast Bridge')
    .addParam('initTokenTransferArg', 'argument for token transfer initialization')
    .setAction(async taskArgs => {
        const { initTokenTransfer } = require('./scripts/utils');
        await initTokenTransfer(hre.ethers.provider, taskArgs.fastBridgeAddress, taskArgs.initTokenTransferArg);
    });

task('unlock', 'Init Token Transfer from Aurora to Eth')
    .addParam('fastBridgeAddress', 'Eth address of Aurora Fast Bridge')
    .addParam('nonce', 'nonce')
    .setAction(async taskArgs => {
        const { unlock } = require('./scripts/utils');
        await unlock(hre.ethers.provider, taskArgs.fastBridgeAddress, taskArgs.nonce);
    });

module.exports = {
    solidity: "0.8.17",
    networks: {
        testnet_aurora: {
            url: 'https://testnet.aurora.dev',
            accounts: [`0x${AURORA_PRIVATE_KEY}`]
        },
        develop_aurora: {
            url: 'https://develop.rpc.testnet.aurora.dev:8545',
            accounts: [`0x${AURORA_PRIVATE_KEY}`]
        },
        ropsten: {
            url: 'https://rpc.testnet.aurora.dev:8545',
            accounts: [`0x${AURORA_PRIVATE_KEY}`]
        }
    }
};

