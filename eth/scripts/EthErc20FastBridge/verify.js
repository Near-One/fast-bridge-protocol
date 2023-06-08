const { verify } = require("../utilities/helpers");

const main = async () => {
    const tokensAddresses = Object.values(require("../deployment/deploymentAddresses.json").tokens);
    const whitelistedTokens = Object.values(require("../deployment/deploymentAddresses.json").whitelisted_tokens);
    const network = (await ethers.getDefaultProvider().getNetwork());
    const bridgeAddress = require("../deployment/deploymentAddresses.json")[network.name].new.bridge;

    console.log("Verifing Contract");
    await verify(bridgeAddress, [tokensAddresses, whitelistedTokens]);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

exports.verifyBridge = main