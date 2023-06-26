require("dotenv").config();
require("@nomicfoundation/hardhat-toolbox");
require("@nomicfoundation/hardhat-chai-matchers");
require("@nomiclabs/hardhat-ethers");
require("@nomicfoundation/hardhat-network-helpers");
require("hardhat-contract-sizer");
require("hardhat-abi-exporter");
require("@openzeppelin/hardhat-upgrades");
const { task } = require("hardhat/config");
const deploymentAddress = require("./scripts/deployment/deploymentAddresses.json");
const bridgeArtifacts = require("./artifacts/contracts/EthErc20FastBridge.sol/EthErc20FastBridge.json");
const { boolean } = require("hardhat/internal/core/params/argumentTypes");
require("hardhat-storage-layout");

const PRIVATE_KEYS = process.env.PRIVATE_KEYS ? process.env.PRIVATE_KEYS.split(",") : [];
const PRIVATE_KEY = process.env.PRIVATE_KEY || "11".repeat(32);

const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY;
const INFURA_API_KEY = process.env.INFURA_API_KEY;

const FORKING = true;
const ENABLED_OPTIMIZER = true;
const OPTIMIZER_RUNS = 200;

task("method", "Execute Fastbridge methods")
    .addParam("jsonstring", "JSON string with function signature and arguments")
    .addParam("gasLimit", "gas-limit for sending transaction")
    .setAction(async (taskArgs) => {
        const { ethers } = require("hardhat");
        const network = (await ethers.getDefaultProvider().getNetwork()).name;
        const bridgeAddress = deploymentAddress[network].new.bridge;
        const provider = new ethers.providers.JsonRpcProvider(process.env.RPC_TASK);
        const signer = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

        const jsonString = taskArgs.jsonstring;
        const json = JSON.parse(jsonString);
        const arg = json.arguments;
        const functionSignature = json.signature;
        console.log(arg);
        const functionArguments = Object.values(arg);
        console.log(functionSignature, functionArguments);
        const iface = new ethers.utils.Interface(bridgeArtifacts.abi);
        // Send the transaction
        const txdata = iface.encodeFunctionData(functionSignature, functionArguments);
        const tx = await signer.sendTransaction({
            to: bridgeAddress,
            data: txdata,
            gasLimit: taskArgs.gasLimit
        });
        console.log(tx);
        await tx.wait();

        console.log("Transaction mined!");
    });

task("deploy_fastbridge", "Deploys Eth-Erc20 Fastbridge and whitelists tokens in deploymentAddress.json")
    .addParam("verification", "Verify the deployed fastbridge on same network", false, boolean)
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const deploy_fast_bridge = require("./scripts/deployment/deploy-bridge.js");
        await deploy_fast_bridge(taskArgs.verification);
    });

task("verify_bridge", "verifies the already deployed contract on same network")
    .addParam("proxyAddress", "Proxy address of already deployed fast-bridge contract")
    .setAction(async (taskArgs) => {
        const { verify } = require("./scripts/deployment/utilities/helpers.js");
        await verify(taskArgs.proxyAddress, []);
    });

task("whitelists_token", "Whitelists erc-20 token in fast-bridge by authorised whitelisting-admin-signer")
    .addParam("tokenAddress", "Address of token to be whitelisted")
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const { addTokenToWhitelist } = require("./scripts/EthErc20FastBridge/whitelistTokens.js");
        const [whitelistingAdminSigner] = await hre.ethers.getSigners();
        await addTokenToWhitelist(taskArgs.tokenAddress, whitelistingAdminSigner);
    });

task("is_token_whitelisted", "Check if token is whitelisted or not")
    .addParam("tokenAddress", "Token address to check for whitelist")
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const { isTokenInWhitelist } = require("./scripts/EthErc20FastBridge/whitelistTokens.js");
        await isTokenInWhitelist(taskArgs.tokenAddress);
    });

task("remove_token_from_whitelists", "Removes erc-20 token from whitelists")
    .addParam("tokenAddress", "Token address to remove from whitelists")
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const [whitelistingAdminSigner] = await hre.ethers.getSigners();
        const { removeTokenFromWhitelist } = require("./scripts/EthErc20FastBridge/whitelistTokens.js");
        await removeTokenFromWhitelist(taskArgs.tokenAddress, whitelistingAdminSigner);
    });

task(
    "whitelists_token_in_bulk",
    "Whitelists erc-20 tokens in fast-bridge by authorised whitelisting-admin-signer in bulk"
)
    .addParam("tokenAddresses", "Comma separated token addresses to whitelists")
    .addParam("whitelistsStatus", "Comma separated bool values for associated tokens whitelist status")
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const [whitelistingAdminSigner] = await hre.ethers.getSigners();
        const tokenAddresses = taskArgs.tokenAddresses.split(",");
        const whitelistsStatus = taskArgs.whitelistsStatus.split(",");
        const { bulkWhitelistStatusUpdate } = require("./scripts/EthErc20FastBridge/whitelistTokens.js");
        await bulkWhitelistStatusUpdate(tokenAddresses, whitelistsStatus, whitelistingAdminSigner);
    });

task("withdraw_stuck_tokens", "Withdraw stucked erc-20 tokens in fast bridge (caller with DEFAULT_ADMIN_ROLE)")
    .addParam("tokenAddress", "Address of stucked token")
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const [defaultAdminSigner] = await hre.ethers.getSigners();
        const { withdrawStuckTokens } = require("./scripts/EthErc20FastBridge/withdraw_Stuck_tokens.js");
        await withdrawStuckTokens(taskArgs.tokenAddress, defaultAdminSigner);
    });

task("pause_fastbridge", "Pause all user-accessible operations in fast-bridge").setAction(async (_taskArgs, hre) => {
    await hre.run("compile");
    const [pauseableAdminSigner] = await hre.ethers.getSigners();
    const { pauseTransfer } = require("./scripts/EthErc20FastBridge/pause_unpause.js");
    await pauseTransfer(pauseableAdminSigner);
});

task("unpause_fastbridge", "Unpause all user-accessible operations in fast-bridge").setAction(
    async (_taskArgs, hre) => {
        await hre.run("compile");
        const [unPauseableAdminSigner] = await hre.ethers.getSigners();
        const { unpauseTransfer } = require("./scripts/EthErc20FastBridge/pause_unpause.js");
        await unpauseTransfer(unPauseableAdminSigner);
    }
);

module.exports = {
    solidity: {
        version: "0.8.11",
        settings: {
            optimizer: {
                enabled: ENABLED_OPTIMIZER,
                runs: OPTIMIZER_RUNS
            },
            metadata: {
                // do not include the metadata hash, since this is machine dependent
                // and we want all generated code to be deterministic
                // https://docs.soliditylang.org/en/v0.8.11/metadata.html
                bytecodeHash: "none"
            }
        }
    },
    networks: {
        hardhat: {
            allowUnlimitedContractSize: !ENABLED_OPTIMIZER,
            forking: {
                url: process.env.FORKING_URL || `https://mainnet.infura.io/v3/${INFURA_API_KEY}`,
                enabled: FORKING !== undefined
            }
        },
        mainnet: {
            url: process.env.MAINNET_URL || "",
            accounts: [...PRIVATE_KEYS]
        },
        rinkeby: {
            url: process.env.RINKEBY_URL || "",
            accounts: [...PRIVATE_KEYS]
        },
        ropsten: {
            url: process.env.ROPSTEN_URL || "",
            accounts: [...PRIVATE_KEYS]
        },
        kovan: {
            url: process.env.KOVAN_URL || "",
            accounts: [...PRIVATE_KEYS]
        },
        goerli: {
            url: INFURA_API_KEY
                ? `https://goerli.infura.io/v3/${INFURA_API_KEY}`
                : `https://eth-goerli.alchemyapi.io/v2/${ALCHEMY_API_KEY}`,
            accounts: [`${PRIVATE_KEY}`]
        },
        mumbai: {
            url: INFURA_API_KEY
                ? `https://mumbai.infura.io/v3/${INFURA_API_KEY}`
                : `https://polygon-mumbai.g.alchemy.com/v2/${ALCHEMY_API_KEY}`,
            accounts: [`${PRIVATE_KEY}`]
        }
    },
    gasReporter: {
        enabled: process.env.REPORT_GAS !== undefined,
        currency: "USD",
        outputFile: process.env.GAS_REPORT_TO_FILE ? "gas-report.txt" : undefined
    },
    etherscan: {
        apiKey: process.env.ETHERSCAN_API_KEY,
        url: process.env.ETHERSCAN_URL || ""
    },
    contractSizer: {
        except: ["mocks/"]
    },
    abiExporter: {
        pretty: true,
        except: ["interfaces/", "mocks/"]
    }
};

if (process.env.FORKING_BLOCK_NUMBER)
    module.exports.networks.hardhat.forking.blockNumber = +process.env.FORKING_BLOCK_NUMBER;

if (process.env.HARDFORK) module.exports.networks.hardhat.hardfork = process.env.HARDFORK;
