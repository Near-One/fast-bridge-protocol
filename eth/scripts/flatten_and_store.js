const Straightener = require("sol-straightener");
const fs = require("fs");

// const path = require("path");

async function main() {
    let result = await Straightener.straighten("./contracts/EthErc20FastBridge.sol");
    // solc.
    // console.log(result);
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
    writeToFile("./contracts/EthErc20FastBridge_flat.sol", correctedData);
}

function writeToFile(fileName, data) {
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
