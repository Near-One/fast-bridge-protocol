require("dotenv").config();
require("@nomicfoundation/hardhat-toolbox");
require("@nomicfoundation/hardhat-chai-matchers");
require("@nomiclabs/hardhat-ethers");
require("@nomicfoundation/hardhat-network-helpers");
require("hardhat-contract-sizer");
require("hardhat-abi-exporter");
require("@openzeppelin/hardhat-upgrades");
require("./scripts/EthErc20FastBridge/tasks.js");
require("hardhat-storage-layout");

const PRIVATE_KEYS = process.env.PRIVATE_KEYS ? process.env.PRIVATE_KEYS.split(",") : [];
const PRIVATE_KEY = process.env.PRIVATE_KEY || "11".repeat(32);

const ALCHEMY_API_KEY = process.env.ALCHEMY_API_KEY;
const INFURA_API_KEY = process.env.INFURA_API_KEY;

const FORKING = true;
const ENABLED_OPTIMIZER = true;
const OPTIMIZER_RUNS = 200;

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
