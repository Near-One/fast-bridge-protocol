const hre = require("hardhat");
const fs = require("fs");
const { ethers } = hre;

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
            // .catch(console.error);
            .catch(() => console.log("Verification failed"));
        // console.log("Verification is completed")
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

exports.sleep = sleep;
exports.verify = verify;
exports.getAddressSaver = getAddressSaver;
