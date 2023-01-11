const { getBridge } = require("./whitelistTokens");

async function withdrawStuckTokens(signer) {
    let bridge;
    try {
        bridge = await getBridge();
        await bridge.connect(signer).withdrawStuckTokens();
    } catch (error) {
        console.log("Failed to withdraw", error);
    }
}

module.exports = {
    withdrawStuckTokens
};
