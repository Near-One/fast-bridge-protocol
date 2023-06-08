const {deployBridge} = require("./deploy-bridge");
const {deployTestToken} = require("./deploy-test-tokens");

const main = async () => {
    console.log("deploying test tokens");
    await deployTestToken();
    console.log("deploying bridge with tokens whitelisted");
    await deployBridge();
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});