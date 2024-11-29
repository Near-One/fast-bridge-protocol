const { getBridge } = require("./whitelistTokens");

async function transferTokens(signer, token, recipient, nonce, amount, unlock_recipient, valid_till_block_height) {
    let bridge;
    try {
        bridge = await getBridge();
        await bridge
            .connect(signer)
            .transferTokens(token, recipient, nonce, amount, unlock_recipient, valid_till_block_height);
    } catch (error) {
        console.log("Failed to transfer tokens", error);
    }
}
module.exports = {
    transferTokens
};
