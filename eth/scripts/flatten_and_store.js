const Straightener = require("sol-straightener");
const fs = require("fs");
const solc = require("solc");

async function main() {
    let result = await Straightener.straighten("./contracts/EthErc20FastBridge.sol");

    let lines = result.split("\n");
    let foundFirst = false;
    let corrected = [];

    lines.forEach((line) => {
        if (line.startsWith("// SPDX-License-Identifier: MIT")) {
            if (!foundFirst) {
                foundFirst = true;
                corrected.push(line);
            }
        } else {
            corrected.push(line);
        }
    });

    let correctedData = corrected.join("\n");
    await writeToFile("./res/EthErc20FastBridge_flat.sol", correctedData);
    await sleep(2 * 1000);

    // compile contract
    let input = {
        language: "Solidity",
        sources: {
            "EthErc20FastBridge_flat.sol": {
                content: correctedData.toString()
            }
        },
        settings: {
            outputSelection: {
                "*": {
                    "*": ["*"]
                }
            }
        }
    };

    const compiled = await JSON.parse(solc.compile(JSON.stringify(input)));
    console.log(compiled);
    const abi = compiled.contracts["EthErc20FastBridge_flat.sol"].EthErc20FastBridge.abi;
    await writeToFile("./res/EthErc20FastBridge_abi.json", JSON.stringify(abi, null, 2));

    const bytecode = compiled.contracts["EthErc20FastBridge_flat.sol"].EthErc20FastBridge.evm.bytecode;
    const deployedBytecode = compiled.contracts["EthErc20FastBridge_flat.sol"].EthErc20FastBridge.evm.deployedBytecode;
    const data = {
        bytecode: bytecode.object.toString(),
        deployedBytecode: deployedBytecode.object.toString()
    };
    await writeToFile("./res/EthErc20FastBridge_bytecode.json", JSON.stringify(data, null, 2));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function writeToFile(fileName, data) {
    fs.open(fileName, "wx", (err) => {
        if (err) {
            if (err.code === "EEXIST") {
                console.log(`${fileName} already exists, rewriting...`);
                fs.writeFile(fileName, data, (err) => {
                    if (err) throw err;
                    console.log("The file has been saved!");
                });
            } else {
                throw err;
            }
        } else {
            console.log(`${fileName} does not exist, creating...`);
            fs.writeFile(fileName, data, (err) => {
                if (err) throw err;
                console.log("The file has been saved!");
            });
        }
    });
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
