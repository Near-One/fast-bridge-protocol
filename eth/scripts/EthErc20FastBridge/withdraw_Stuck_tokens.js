const { getBridge } = require("./whitelistTokens");

async function withdrawStuckTokens(signer) {
    const bridge = await getBridge();
    await bridge.connect(signer).withdrawStuckTokens();
}

module.exports = {
    withdrawStuckTokens
};
