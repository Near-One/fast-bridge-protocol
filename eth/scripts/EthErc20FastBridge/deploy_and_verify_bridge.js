const { deployBridge } = require("../deployment/deploy-bridge");
const { verifyBridge } = require("./verify");

const main = async () => {
    await deployBridge();
    // verify
    await verifyBridge();
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
