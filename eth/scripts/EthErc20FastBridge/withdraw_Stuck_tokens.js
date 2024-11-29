const { getBridge } = require("./whitelistTokens");

async function withdrawStuckTokens(token, signer) {
    let bridge;
    try {
        bridge = await getBridge();
        await bridge.connect(signer).withdrawStuckTokens(token);
    } catch (error) {
        console.log("Failed to withdraw", error);
    }
}

module.exports = {
    withdrawStuckTokens
};
