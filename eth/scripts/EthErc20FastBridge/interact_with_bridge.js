const { ethers } = require("hardhat");
const {
    bulkWhitelistStatusUpdate,
    addTokenToWhitelist,
    removeTokenFromWhitelist,
    isTokenInWhitelist
} = require("./whitelistTokens");
const { pauseTransfer, unpauseTransfer } = require("./pause_unpause");
const { withdrawStuckTokens } = require("./withdraw_Stuck_tokens");
const prompt = require("prompt-sync")();

async function main() {
    console.log(
        "Please select operation to perform on Bridge :\n" +
            "1. Bulk whitelist Tokens\n" +
            "2. Add one token to whitelist\n" +
            "3. Remove token from whitelist\n" +
            "4. Check token's whitelist status\n" +
            "5. Pause transfers\n" +
            "6. Unpause transfers\n" +
            "7. Withdraw stuck tokens\n"
    );

    const choice = prompt("Please Enter your choice :");
    if (choice !== null) {
        let userInput = choice.toString().trim().toLowerCase();
        if (userInput === "1") {
            console.log("to execute bulkWhitelistStatusUpdate(tokensArray, statusArray, signer)");
            const inputTokens = prompt("please enter space separated token addresses : ");
            let addressArray = inputTokens.trim().split(" ");
            const inputStatuses = prompt("please enter space separated token whitelists status in bool : ");
            let statusArray = inputStatuses.trim().split(" ");
            console.log(addressArray);

            const [whitelistingAdminSigner] = await ethers.getSigners();
            if (addressArray.length == statusArray) {
                await bulkWhitelistStatusUpdate(addressArray, statusArray, whitelistingAdminSigner);
            } else {
                console.log("number of tokens is not equal to number of statuses provided");
            }
        } else if (userInput === "2") {
            console.log("to execute addTokenToWhitelist(token, signer)");
            const inputToken = prompt("please enter token address : ");
            let tokenAddress = inputToken.trim();
            const [whitelistingAdminSigner] = await ethers.getSigners();
            await addTokenToWhitelist(tokenAddress, whitelistingAdminSigner);
        } else if (userInput === "3") {
            console.log("to execute removeTokenFromWhitelist(token, signer)");
            const inputToken = prompt("please enter token address : ");
            let tokenAddress = inputToken.trim();
            const [whitelistingAdminSigner] = await ethers.getSigners();
            await removeTokenFromWhitelist(tokenAddress, whitelistingAdminSigner);
        } else if (userInput === "4") {
            console.log("to execute isTokenInWhitelist(token)");
            const inputToken = prompt("please enter token address : ");
            let token = inputToken.trim();
            await isTokenInWhitelist(token);
        } else if (userInput === "5") {
            console.log("to execute pauseTransfer(signer)");
            const [pausableAdminSigner] = await ethers.getSigners();
            await pauseTransfer(pausableAdminSigner);
        } else if (userInput === "6") {
            console.log("Executing unpauseTransfer(signer)");
            const [unpausableAdminSigner] = await ethers.getSigners();
            await unpauseTransfer(unpausableAdminSigner);
        } else if (userInput === "7") {
            console.log("to execute withdrawStuckTokens(signer)");
            const [defaultAdminSigner] = await ethers.getSigners();
            await withdrawStuckTokens(defaultAdminSigner);
        } else {
            // Handle invalid input
            console.log("Invalid input.");
        }
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
