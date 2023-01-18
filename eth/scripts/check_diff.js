const fs = require("fs");
const solc = require("solc");

async function main() {
    var input = {
        language: "Solidity",
        sources: {
            ["EthErc20FastBridge.sol"]: {
                content: fs.readFileSync("contracts/EthErc20FastBridge.sol", "utf8")
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
    const compiledData = await JSON.parse(solc.compile(JSON.stringify(input))); // WIP: add check imports
    console.log(compiledData);

    // get new bytecode
    const resBytecode = fs.readFileSync("/res/EthErc20FastBridge_bytecode.json", "utf8").deployedBytecode;

    // check if bytecodes are same
    if (
        compiledData.contracts["EthErc20FastBridge.sol"].EthErc20FastBridge.evm.deployedBytecode.object.toString() !=
        resBytecode
    ) {
        // fail CI
        console.log("failed");
    } else {
        console.log("passed");
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
