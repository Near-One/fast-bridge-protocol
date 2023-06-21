const hre = require("hardhat");
const fs = require("fs");
const { ethers } = hre;
const deploymentAddress = require("../deploymentAddresses.json");

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function verify(address, args) {
    if (hre.network.name !== "hardhat" && hre.network.name !== "localhost") {
        let retry = 20;
        console.log("Sleeping before verification...");
        while ((await ethers.provider.getCode(address).catch(() => "")).length <= 3 && retry >= 0) {
            await sleep(5000);
            --retry;
        }
        await sleep(30000);

        console.log(address, args);

        await hre
            .run("verify:verify", {
                address,
                constructorArguments: args
            })
            .catch(() => console.log("Verification failed"));
    }
}

function getAddressSaver(path, network, isLog) {
    const addresses = require(path);
    if (!addresses[network]) {
        addresses[network] = {};
    }
    if (!addresses[network].old) {
        addresses[network].old = {};
    }
    if (!addresses[network].new) {
        addresses[network].new = {};
    }
    function saveAddress(contractName, address, isNewMigration) {
        if (isNewMigration) {
            addresses[network].old = addresses[network].new;
            addresses[network].new = {};
        }
        addresses[network].new[contractName] = address;
        if (isLog) console.log(`${contractName} deployed to ${address}`);
        fs.writeFileSync(path, JSON.stringify(addresses, null, 4));
        return addresses[network].new;
    }
    return saveAddress;
}

async function getBridgeContract() {
    console.log("Connecting with bridge...");
    const network = (await ethers.getDefaultProvider().getNetwork()).name;
    const bridgeAddress = deploymentAddress[network].new.bridge_proxy;
    const bridge = ethers.getContractAt("/contracts/EthErc20FastBridge.sol:EthErc20FastBridge", bridgeAddress);
    console.log("Connected !");
    return bridge;
}

exports.sleep = sleep;
exports.verify = verify;
exports.getAddressSaver = getAddressSaver;
exports.getBridgeContract = getBridgeContract;
