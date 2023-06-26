const { task } = require("hardhat/config");
const { boolean } = require("hardhat/internal/core/params/argumentTypes");
const deploymentAddress = require("../deployment/deploymentAddresses.json");
const bridgeArtifacts = require("../../artifacts/contracts/EthErc20FastBridge.sol/EthErc20FastBridge.json");

task("method", "Execute Fastbridge methods")
    .addParam("jsonstring", "JSON string with function signature and arguments")
    .setAction(async (taskArgs, hre) => {
        const network = (await hre.ethers.getDefaultProvider().getNetwork()).name;
        const bridgeAddress = deploymentAddress[network].new.bridge;
        const provider = new hre.ethers.providers.JsonRpcProvider(process.env.RPC_TASK);
        const signer = new hre.ethers.Wallet(process.env.PRIVATE_KEY, provider);

        const jsonString = taskArgs.jsonstring;
        const json = JSON.parse(jsonString);
        const arg = json.arguments;
        const functionSignature = json.signature;
        console.log(arg);
        const functionArguments = Object.values(arg);
        console.log(functionSignature, functionArguments);
        const iface = new hre.ethers.utils.Interface(bridgeArtifacts.abi);
        // Send the transaction
        const txdata = iface.encodeFunctionData(functionSignature, functionArguments);
        const tx = await signer.sendTransaction({
            to: bridgeAddress,
            data: txdata,
            gasLimit: 999999
        });
        console.log(tx);
        await tx.wait();

        console.log("Transaction mined!");
    });
task("deploy_fastbridge", "Deploys Eth-Erc20 Fastbridge and whitelists tokens in deploymentAddress.json")
    .addParam("verification", "Verify the deployed fastbridge on same network", false, boolean)
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const deploy_fast_bridge = require("../deployment/deploy-bridge.js");
        await deploy_fast_bridge(taskArgs.verification);
    });

task("verify_bridge", "verifies the already deployed contract on same network")
    .addParam("proxyAddress", "Proxy address of already deployed fast-bridge contract")
    .setAction(async (taskArgs) => {
        const { verify } = require("../deployment/utilities/helpers.js");
        await verify(taskArgs.proxyAddress, []);
    });

task("whitelists_token", "Whitelists erc-20 token in fast-bridge by authorised whitelisting-admin-signer")
    .addParam("tokenAddress", "Address of token to be whitelisted")
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const { addTokenToWhitelist } = require("./whitelistTokens.js");
        const [whitelistingAdminSigner] = await hre.ethers.getSigners();
        await addTokenToWhitelist(taskArgs.tokenAddress, whitelistingAdminSigner);
    });

task("is_token_whitelisted", "Check if token is whitelisted or not")
    .addParam("tokenAddress", "Token address to check for whitelist")
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const { isTokenInWhitelist } = require("./whitelistTokens.js");
        await isTokenInWhitelist(taskArgs.tokenAddress);
    });

task("remove_token_from_whitelists", "Removes erc-20 token from whitelists")
    .addParam("tokenAddress", "Token address to remove from whitelists")
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const [whitelistingAdminSigner] = await hre.ethers.getSigners();
        const { removeTokenFromWhitelist } = require("./whitelistTokens.js");
        await removeTokenFromWhitelist(taskArgs.tokenAddress, whitelistingAdminSigner);
    });

task(
    "whitelists_token_in_bulk",
    "Whitelists erc-20 tokens in fast-bridge by authorised whitelisting-admin-signer in bulk"
)
    .addParam("tokenAddresses", "Comma separated token addresses to whitelists")
    .addParam("whitelistsStatus", "Comma separated bool values for associated tokens whitelist status")
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const [whitelistingAdminSigner] = await hre.ethers.getSigners();
        const tokenAddresses = taskArgs.tokenAddresses.split(",");
        const whitelistsStatus = taskArgs.whitelistsStatus.split(",");
        const { bulkWhitelistStatusUpdate } = require("./whitelistTokens.js");
        await bulkWhitelistStatusUpdate(tokenAddresses, whitelistsStatus, whitelistingAdminSigner);
    });

task("withdraw_stuck_tokens", "Withdraw stucked erc-20 tokens in fast bridge (caller with DEFAULT_ADMIN_ROLE)")
    .addParam("tokenAddress", "Address of stucked token")
    .setAction(async (taskArgs, hre) => {
        await hre.run("compile");
        const [defaultAdminSigner] = await hre.ethers.getSigners();
        const { withdrawStuckTokens } = require("./withdraw_Stuck_tokens.js");
        await withdrawStuckTokens(taskArgs.tokenAddress, defaultAdminSigner);
    });

task("pause_fastbridge", "Pause all user-accessible operations in fast-bridge").setAction(async (_taskArgs, hre) => {
    await hre.run("compile");
    const [pauseableAdminSigner] = await hre.ethers.getSigners();
    const { pauseTransfer } = require("./pause_unpause.js");
    await pauseTransfer(pauseableAdminSigner);
});

task("unpause_fastbridge", "Unpause all user-accessible operations in fast-bridge").setAction(
    async (_taskArgs, hre) => {
        await hre.run("compile");
        const [unPauseableAdminSigner] = await hre.ethers.getSigners();
        const { unpauseTransfer } = require("./pause_unpause.js");
        await unpauseTransfer(unPauseableAdminSigner);
    }
);

task("upgrade_fastbridge", "Upgrade fast-bridge contract (Only signer with DEFAULT_ADMIN_ROLE can do this)").setAction(
    async (_taskArgs, hre) => {
        await hre.run("compile");
        const [defaultAdminSigner] = await hre.ethers.getSigners();
        const { upgradeFastBridge } = require("./upgrade_bridge.js");
        await upgradeFastBridge(defaultAdminSigner);
    }
);
