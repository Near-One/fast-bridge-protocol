const { task } = require("hardhat/config");
require("dotenv").config();
require("@nomicfoundation/hardhat-toolbox");

require("@nomicfoundation/hardhat-chai-matchers");
require("@nomiclabs/hardhat-ethers");
require("@nomicfoundation/hardhat-network-helpers");

require("hardhat-contract-sizer");
require("hardhat-abi-exporter");
require("@openzeppelin/hardhat-upgrades");
require("hardhat-storage-layout");

const PRIVATE_KEYS = process.env.PRIVATE_KEYS ? process.env.PRIVATE_KEYS.split(",") : [];
const PRIVATE_KEY = process.env.PRIVATE_KEY || "11".repeat(32);

const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY;
const INFURA_API_KEY = process.env.INFURA_API_KEY;

const FORKING = true; // set undefined to disable forking
const ENABLED_OPTIMIZER = true;
const OPTIMIZER_RUNS = 200;

task("deploy_fastbridge_with_token", "Deploys Eth erc20 Fastbridge with erc20 tokens and whitelists them").setAction(
    async (_taskArgs, hre) => {
        await hre.run("compile");
        const { bridge_deployment_task } = require("./scripts/deployment/deploy_bridge_ETH.js");
        await bridge_deployment_task();
    }
);

task("getBlockHash", "returns the block hash of input block number")
    .addParam("blocknumber", "Block number in integer")
    .setAction(async (taskArgs) => {
        const { getBlockHash } = require("./scripts/deployment/deploy_bridge_ETH.js");
        await getBlockHash(taskArgs.blockNumber);
    });

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
        ganache: {
            url: "HTTP://127.0.0.1:7545",
            allowUnlimitedContractSize: true
        },
        localnet: {
            url: "HTTP://127.0.0.1:8545",
            allowUnlimitedContractSize: true
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
