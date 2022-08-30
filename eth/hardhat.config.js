require("dotenv").config();

require("@nomicfoundation/hardhat-toolbox");

require("@nomicfoundation/hardhat-chai-matchers");
require("@nomiclabs/hardhat-ethers");
require("@nomicfoundation/hardhat-network-helpers");

require("hardhat-contract-sizer");
require("hardhat-abi-exporter");
require("@openzeppelin/hardhat-upgrades");

const PRIVATE_KEYS = process.env.PRIVATE_KEYS ? process.env.PRIVATE_KEYS.split(",") : [];
const ENABLED_OPTIMIZER = true;
const OPTIMIZER_RUNS = 200; 

module.exports = {
    solidity: {
        compilers: [
            {
                version: "0.8.11",
                settings: {
                    optimizer: {
                        enabled: ENABLED_OPTIMIZER,
                        runs: OPTIMIZER_RUNS
                    }
                }
            }
        ]
    },
    networks: {
        hardhat: {
            allowUnlimitedContractSize: !ENABLED_OPTIMIZER,
            forking: {
                url: process.env.FORKING_URL || "https://eth-mainnet.g.alchemy.com/v2/YIMyfAgTDcuPIBL5V9VAhRNug0wEqSvT",
                enabled: process.env.FORKING !== undefined
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

if (process.env.HARDFORK)
    module.exports.networks.hardhat.hardfork = process.env.HARDFORK;
