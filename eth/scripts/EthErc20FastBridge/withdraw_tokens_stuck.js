const { getBridgeContract } = require("../utilities/helpers");

async function withdrawStuckTokens(signer) {
    let bridge;
    try {
        bridge = await getBridgeContract();
        await bridge.connect(signer).withdrawStuckTokens();
    } catch (error) {
        console.log("Failed to withdraw", error);
    }
}

module.exports = {
    withdrawStuckTokens
};
