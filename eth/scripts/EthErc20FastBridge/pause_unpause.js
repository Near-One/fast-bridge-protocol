const { getBridgeContract } = require("../utilities/helpers");

async function pauseTransfer(signer) {
    let bridge;
    try {
        bridge = await getBridgeContract();
        await bridge.connect(signer).pause();
        console.log("Transfers paused successfully!");
    } catch (error) {
        console.error("Transfers pause failed with error", error);
    }
}

async function unpauseTransfer(signer) {
    let bridge;
    try {
        bridge = await getBridgeContract();
        await bridge.connect(signer).unPause();
        console.log("Transfers unpaused successfully!");
    } catch (error) {
        console.error("Transfers unpause failed with error", error);
    }
}

module.exports = {
    pauseTransfer,
    unpauseTransfer
};
