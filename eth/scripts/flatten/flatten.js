const { gatherSources } = require("@resolver-engine/imports");
const { ImportsFsEngine } = require("@resolver-engine/imports-fs");
const fs = require("fs");
const path = require("path");

// Script
const resultsDir = "./json_inputs";
let contracts = [];
let recursiveCounter = 0;

if (!fs.existsSync(resultsDir)) {
    fs.mkdirSync(resultsDir);
}
const contractsPaths = getContractsPaths(process.argv[2]);

contractsPaths.map((contractPath) => {
    generateJson(contractPath);
});

// Json input generation
async function getSolidityInput(contractPath) {
    let input = await gatherSources([contractPath], process.cwd(), ImportsFsEngine());
    input = input.map((obj) => ({ ...obj, url: obj.url.replace(`${process.cwd()}/`, "") }));

    const sources = {};
    for (const file of input) {
        sources[file.url] = { content: file.source };
    }

    const inputJSON = {
        language: "Solidity",
        settings: {
            outputSelection: {
                "*": {
                    "*": ["abi", "evm.bytecode", "evm.deployedBytecode"]
                }
            },
            optimizer: {
                enabled: true,
                runs: 200
            }
        },
        sources
    };

    return JSON.stringify(inputJSON, null, 2);
}

// Write json input files
async function generateJson(solPath) {
    const contractName = path.basename(solPath).slice(0, -4);
    fs.writeFileSync(`${resultsDir}/${contractName}.json`, await getSolidityInput(solPath));
    console.log(`Generated ${resultsDir}/${contractName}.json`);
}

// Recursively get path and filter only .sol files
function getContractsPaths(dir) {
    recursiveCounter++;
    if (fs.lstatSync(dir).isDirectory())
        fs.readdirSync(dir).forEach((file) => {
            let fullPath = path.join(dir, file);
            if (fs.lstatSync(fullPath).isDirectory()) {
                getContractsPaths(fullPath);
            } else {
                if (isSol(fullPath)) contracts.push(fullPath);
            }
        });
    else {
        if (isSol(dir)) return [dir];
        else throw new Error("Not .sol file");
    }
    recursiveCounter--;
    if (recursiveCounter == 0) {
        const contractsPaths = contracts;
        contracts = [];
        return contractsPaths;
    } else return;
}

// Check if file has .sol extension
function isSol(str) {
    return path.extname(str) == ".sol";
}
