const { getBridge } = require("./whitelistTokens");

async function pauseTransfer(signer) {
    const bridge = await getBridge();
    await bridge.connect(signer).pause();
}

async function unPauseTransfer(signer) {
    const bridge = await getBridge();
    await bridge.connect(signer).unpause();
}

module.exports = {
    pauseTransfer,
    unPauseTransfer
};
