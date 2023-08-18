// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
require('dotenv').config();
const hre = require("hardhat");

async function deploy({
                          signer,
                          nearFastBridgeAccount,
                          auroraEngineAccountId,
                          wNearAddress,
                          auroraSdkAddress,
                          auroraUtilsAddress
                      }
) {
    console.log("Deploying contracts with the account:", signer.address);
    console.log(
        "Account balance:",
        (await signer.provider.getBalance(signer.address)).toString(),
    );

    const AuroraErc20FastBridge = (await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
        libraries: {
            "AuroraSdk": auroraSdkAddress,
            "Utils": auroraUtilsAddress
        },
    })).connect(signer);

    let proxy = await hre.upgrades.deployProxy(AuroraErc20FastBridge,
        [wNearAddress, nearFastBridgeAccount, auroraEngineAccountId, true],
        {
        initializer: "initialize",
        unsafeAllowLinkedLibraries: true,
        gasLimit: 6000000
    });
    await proxy.waitForDeployment();

    console.log("AuroraErc20FastBridge proxy deployed to:", await proxy.getAddress());
    console.log(
        "AuroraErc20FastBridge impl deployed to: ",
        await hre.upgrades.erc1967.getImplementationAddress(await proxy.getAddress()),
    );
}

async function upgrade({signer,
                        proxyAddress,
                        auroraSdkAddress,
                        auroraUtilsAddress,
                       }) {
    console.log("Upgrading contracts with the account:", signer.address);
    console.log(
        "Account balance:",
        (await signer.provider.getBalance(signer.address)).toString(),
    );

    const AuroraErc20FastBridge = (
        await hre.ethers.getContractFactory("AuroraErc20FastBridge", {
            libraries: {
                AuroraSdk: auroraSdkAddress,
                Utils: auroraUtilsAddress,
            },
        })
    ).connect(signer);

    console.log(
        "Current implementation address:",
        await hre.upgrades.erc1967.getImplementationAddress(proxyAddress),
    );
    console.log("Upgrade AuroraErc20FastBridge contract, proxy address", proxyAddress);
    const proxy = await hre.upgrades.upgradeProxy(proxyAddress, AuroraErc20FastBridge, {
        unsafeAllowLinkedLibraries: true,
        gasLimit: 6000000,
    });
    await proxy.waitForDeployment();

    console.log(
        "AuroraErc20FastBridge impl deployed to: ",
        await hre.upgrades.erc1967.getImplementationAddress(await proxy.getAddress()),
    );
}

exports.deploy = deploy;
exports.upgrade = upgrade;