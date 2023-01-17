const fs = require("fs");

// const path = require("path");

async function main() {
    await move_fastbridge_flat_to_res();
    await move_binary_to_res();
}

async function move_fastbridge_flat_to_res() {
    const readStream = fs.createReadStream("contracts/EthErc20FastBridge_flat.sol");
    const writeStream = fs.createWriteStream("res/EthErc20FastBridge_flat.sol");

    readStream.pipe(writeStream);

    readStream.on("end", () => {
        console.log("File copied to new location.");
    });
}

async function move_binary_to_res() {
    const readStream = fs.createReadStream("artifacts/contracts/EthErc20FastBridge_flat.sol/EthErc20FastBridge.json");
    const writeStream = fs.createWriteStream("res/EthErc20FastBridge.json");

    readStream.pipe(writeStream);

    readStream.on("end", () => {
        console.log("File copied to new location.");
    });
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
