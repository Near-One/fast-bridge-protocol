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
            nearFastBridgeAccountId: config.nearFastBridgeAccountId,
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

task('register_token', 'Registers a binding of "nearTokenAccountId:auroraTokenAddress" in "AuroraFastBridge" contract.')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAccountId', "Token account id on Near")
    .setAction(async taskArgs => {
        const { registerToken } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await registerToken(signer, config, taskArgs.fastBridgeAddress, taskArgs.nearTokenAccountId);
    });

task('storage_deposit', 'Puts a storage deposit in "nearTokenAccountId" for the "AuroraFastBridge" implicit NEAR Account ID.')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAccountId', "Token account id on Near")
    .setAction(async taskArgs => {
        const { storageDeposit } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await storageDeposit(signer, config, taskArgs.fastBridgeAddress, taskArgs.nearTokenAccountId);
    });

task('init_token_transfer', 'Initialize Token Transfer from Aurora to Ethereum')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('initTokenTransferArg', 'argument for token transfer initialization')
    .addParam('auroraTokenAddress', "Token address on Aurora")
    .setAction(async taskArgs => {
        const { initTokenTransfer } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await initTokenTransfer(signer, config, taskArgs.fastBridgeAddress, taskArgs.initTokenTransferArg, taskArgs.auroraTokenAddress);
    });

task('unlock', 'Unlock tokens on Near')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nonce', 'Nonce of the Fast Bridge transfer')
    .setAction(async taskArgs => {
        const { unlock } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await unlock(signer, config, taskArgs.fastBridgeAddress, taskArgs.nonce);
    });

task('fast_bridge_withdraw_on_near', 'Withdraw tokens on Near side')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAccountId', "Token account id on Near")
    .addParam('tokenAmount', "Withdraw tokens amount")
    .setAction(async taskArgs => {
        const { fast_bridge_withdraw_on_near } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await fast_bridge_withdraw_on_near(signer, config, taskArgs.fastBridgeAddress, taskArgs.nearTokenAccountId, taskArgs.tokenAmount);
    });

task('withdraw_from_implicit_near_account', 'Withdraw tokens to user from Aurora Fast Bridge Implicit Near Account')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('nearTokenAccountId', "Token account id on Near")
    .setAction(async taskArgs => {
        const { withdraw_from_implicit_near_account } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await withdraw_from_implicit_near_account(signer, config, taskArgs.fastBridgeAddress, taskArgs.nearTokenAccountId);
    });

task('set_whitelist_mode_for_users', 'Set whitelist mode for users')
    .addParam("silo", "Config file name without extension")
    .addParam('fastBridgeAddress', 'Aurora Fast Bridge address')
    .addParam('userAddress', "User address")
    .setAction(async taskArgs => {
        const { set_whitelist_mode_for_users } = require('./scripts/utils');
        const [signer] = await hre.ethers.getSigners();
        const config = require(`./configs/${taskArgs.silo}.json`);

        await set_whitelist_mode_for_users(signer, config, taskArgs.fastBridgeAddress, taskArgs.userAddress);
    });

task("set_whitelist_mode", "Set whitelist mode")
  .addParam("silo", "Config file name without extension")
  .addParam("fastBridgeAddress", "Aurora Fast Bridge address")
  .addParam(
    "enabled",
    "Pass `true` to enable or `false` to disable the whitelist mode"
  )
  .setAction(async (taskArgs) => {
    const { setWhitelistMode } = require("./scripts/utils");
    const [signer] = await hre.ethers.getSigners();
    const config = require(`./configs/${taskArgs.silo}.json`);

    await setWhitelistMode(signer, config, taskArgs.fastBridgeAddress);
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
