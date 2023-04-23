/* eslint-disable no-unused-vars */
/* eslint-disable node/no-extraneous-require */
const { expect, use } = require("chai");
const { ethers, upgrades } = require("hardhat");
const { getImplementationAddress } = require("@openzeppelin/upgrades-core");

const { time, takeSnapshot, SnapshotRestorer } = require("@nomicfoundation/hardhat-network-helpers");

const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const Uniswap = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
const tokenAddress = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const unlockRecipient = "near_recipient.near";
const relayerEthAddress = ethers.constants.AddressZero;
const defaultValidTillBlockHeight = 9007199254740991n;

function getTransferId(token, recipient, nonce, amount) {
    return ethers.utils.solidityKeccak256(
        ["address", "address", "uint256", "uint256"],
        [token, recipient, nonce, amount]
    );
}

const buyTokenForEth = async (buyer, router, ethAmount, path) => {
    await router
        .connect(buyer)
        .swapExactETHForTokens(0, path, buyer.address, ethers.constants.MaxUint256, { value: ethAmount });
};

describe("Fast Bridge", () => {
    let router, tokenInstance, weth;
    let owner,
        someone,
        user,
        relayer,
        relayer2,
        relayer3,
        anotherRelayer,
        someoneWithTokens,
        pausableAdmin,
        unpausableAdmin,
        whitelistingAdmin;
    let bridge, proxy;
    let nonce, anotherNonce;
    let snapshotA = SnapshotRestorer;

    before(async () => {
        [
            owner,
            someone,
            user,
            relayer,
            relayer2,
            relayer3,
            anotherRelayer,
            someoneWithTokens,
            pausableAdmin,
            unpausableAdmin,
            whitelistingAdmin
        ] = await ethers.getSigners();
        router = await ethers.getContractAt("IUniswapV2Router01", Uniswap);
        tokenInstance = await ethers.getContractAt("ERC20", tokenAddress);
        weth = await ethers.getContractAt("ERC20", WETH);

        await buyTokenForEth(relayer, router, ethers.utils.parseEther("100", "ether"), [WETH, tokenAddress]);
        await buyTokenForEth(anotherRelayer, router, ethers.utils.parseEther("100", "ether"), [WETH, tokenAddress]);
        let balance = await tokenInstance.balanceOf(relayer.address);
        let someoneBalance = await tokenInstance.balanceOf(someone.address);

        await tokenInstance.connect(relayer).transfer(someoneWithTokens.address, balance.div(2));
        await tokenInstance.connect(someone).transfer(someoneWithTokens.address, someoneBalance);

        bridge = await ethers.getContractFactory("EthErc20FastBridge");
        proxy = await upgrades.deployProxy(bridge, [[], []], { unsafeAllow: ["delegatecall"] });
        await proxy.deployed();

        await proxy.connect(owner).grantRole(await proxy.PAUSABLE_ADMIN_ROLE(), pausableAdmin.address);
        await proxy.connect(owner).grantRole(await proxy.UNPAUSABLE_ADMIN_ROLE(), unpausableAdmin.address);
        await proxy.connect(owner).grantRole(await proxy.WHITELISTING_TOKENS_ADMIN_ROLE(), whitelistingAdmin.address);

        nonce = 11231231;
        anotherNonce = 11231232;

        snapshotA = await takeSnapshot();
    });
    afterEach(async () => await snapshotA.restore());

    describe("Whitelisting", () => {
        const tokensAddresses = [
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "0xB8c77482e45F1F44dE1745F52C74426C631bDD52",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        ];
        const tokensWhitelistStatuses = [true, true, false];

        it("Should add tokens to whitelist", async () => {
            await expect(
                proxy.connect(whitelistingAdmin).setWhitelistedTokens(tokensAddresses, tokensWhitelistStatuses)
            )
                .to.emit(proxy, "SetTokens")
                .withArgs(tokensAddresses, tokensWhitelistStatuses);

            expect(await proxy.isTokenInWhitelist(tokensAddresses[0])).to.be.true;
            expect(await proxy.isTokenInWhitelist(tokensAddresses[1])).to.be.true;
            expect(await proxy.isTokenInWhitelist(tokensAddresses[2])).to.be.false;
        });

        it("Shouldn't setWhitelistedTokens by someone", async () => {
            await expect(proxy.connect(someone).setWhitelistedTokens(tokensAddresses, tokensWhitelistStatuses)).to.be
                .reverted;
        });
    });

    it("Should deploy Bridge with tokens and whitelist states", async () => {
        let tokensAddresses = [
            "0xb2d75C5a142A68BDA438e6a318C7FBB2242f9693",
            "0xa1f5A105d73204b45778983038f733d8867fBea0",
            "0x3195D5df0521d2Fcd5b02413E23e4b1219790767"
        ];
        let tokensWhitelistStatuses = [true, true, false];

        const bridgeV1 = await ethers.getContractFactory("EthErc20FastBridge");
        const proxyV1 = await upgrades.deployProxy(bridgeV1, [tokensAddresses, tokensWhitelistStatuses], {
            unsafeAllow: ["delegatecall"]
        });
        await proxyV1.deployed();

        expect(await proxyV1.isTokenInWhitelist(tokensAddresses[1])).to.be.true;
        expect(await proxyV1.isTokenInWhitelist(tokensAddresses[2])).to.be.false;

        await expect(proxyV1.connect(owner).setWhitelistedTokens([tokensAddresses[2]], [true]))
            .to.emit(proxyV1, "SetTokens")
            .withArgs([tokensAddresses[2]], [true]);

        expect(await proxyV1.isTokenInWhitelist(tokensAddresses[2])).to.be.true;
    });

    describe("Transfer", () => {
        it("Should transfer token", async () => {
            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([tokenAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([tokenAddress], [true]);

            let relayerBalance = await tokenInstance.balanceOf(relayer.address);
            await tokenInstance.connect(relayer).approve(proxy.address, relayerBalance);

            let transferPart = relayerBalance - 100;

            let transferId = getTransferId(tokenAddress, someone.address, nonce, transferPart);
            await expect(
                proxy
                    .connect(relayer)
                    .transferTokens(
                        tokenAddress,
                        someone.address,
                        nonce,
                        transferPart,
                        unlockRecipient,
                        defaultValidTillBlockHeight
                    )
            )
                .to.emit(proxy, "TransferTokens")
                .withArgs(
                    nonce,
                    relayer.address,
                    tokenAddress,
                    someone.address,
                    transferPart,
                    unlockRecipient,
                    transferId
                );

            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(transferPart);

            await proxy.connect(pausableAdmin).pause();

            let relayerBalanceAfter = tokenInstance.balanceOf(relayer.address);
            await expect(
                proxy
                    .connect(relayer)
                    .transferTokens(
                        tokenAddress,
                        someone.address,
                        11231232,
                        relayerBalanceAfter,
                        unlockRecipient,
                        defaultValidTillBlockHeight
                    )
            ).to.be.revertedWith("Pausable: paused");

            await proxy.connect(unpausableAdmin).unPause();

            const amount = 100;
            transferId = getTransferId(tokenAddress, someone.address, anotherNonce, amount);
            await expect(
                proxy
                    .connect(relayer)
                    .transferTokens(
                        tokenAddress,
                        someone.address,
                        anotherNonce,
                        amount,
                        unlockRecipient,
                        defaultValidTillBlockHeight
                    )
            )
                .to.emit(proxy, "TransferTokens")
                .withArgs(
                    anotherNonce,
                    relayer.address,
                    tokenAddress,
                    someone.address,
                    amount,
                    unlockRecipient,
                    transferId
                );

            let transferPart2 = transferPart + 100;
            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(transferPart2);
        });

        it("Shouldn't process the same transfer twice", async () => {
            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([tokenAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([tokenAddress], [true]);

            let balanceRelayer = await tokenInstance.balanceOf(relayer.address);
            await tokenInstance.connect(relayer).approve(proxy.address, balanceRelayer);

            let balanceAnotherRelayer = await tokenInstance.balanceOf(anotherRelayer.address);
            await tokenInstance.connect(anotherRelayer).approve(proxy.address, balanceAnotherRelayer);

            let transferId = getTransferId(tokenAddress, someone.address, nonce, balanceRelayer);
            await expect(
                proxy
                    .connect(anotherRelayer)
                    .transferTokens(
                        tokenAddress,
                        someone.address,
                        nonce,
                        balanceRelayer,
                        unlockRecipient,
                        defaultValidTillBlockHeight
                    )
            )
                .to.emit(proxy, "TransferTokens")
                .withArgs(
                    nonce,
                    anotherRelayer.address,
                    tokenAddress,
                    someone.address,
                    balanceRelayer,
                    unlockRecipient,
                    transferId
                );

            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(balanceRelayer);

            await expect(
                proxy
                    .connect(anotherRelayer)
                    .transferTokens(
                        tokenAddress,
                        someone.address,
                        nonce,
                        balanceRelayer,
                        unlockRecipient,
                        defaultValidTillBlockHeight
                    )
            ).to.be.revertedWith("This transaction has already been processed!");

            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(balanceRelayer);
        });

        it("Should transfer token via two not equal transfers", async () => {
            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([tokenAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([tokenAddress], [true]);

            let balanceRelayer = await tokenInstance.balanceOf(relayer.address);
            await tokenInstance.connect(relayer).approve(proxy.address, balanceRelayer);

            let balanceAnotherRelayer = await tokenInstance.balanceOf(anotherRelayer.address);
            await tokenInstance.connect(anotherRelayer).approve(proxy.address, balanceAnotherRelayer);

            let transferId = getTransferId(tokenAddress, someone.address, nonce, balanceRelayer);
            await expect(
                proxy
                    .connect(relayer)
                    .transferTokens(
                        tokenAddress,
                        someone.address,
                        nonce,
                        balanceRelayer,
                        unlockRecipient,
                        defaultValidTillBlockHeight
                    )
            )
                .to.emit(proxy, "TransferTokens")
                .withArgs(
                    nonce,
                    relayer.address,
                    tokenAddress,
                    someone.address,
                    balanceRelayer,
                    unlockRecipient,
                    transferId
                );
            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(balanceRelayer);

            transferId = getTransferId(tokenAddress, someone.address, anotherNonce, balanceRelayer);
            await expect(
                proxy
                    .connect(anotherRelayer)
                    .transferTokens(
                        tokenAddress,
                        someone.address,
                        anotherNonce,
                        balanceRelayer,
                        unlockRecipient,
                        defaultValidTillBlockHeight
                    )
            )
                .to.emit(proxy, "TransferTokens")
                .withArgs(
                    anotherNonce,
                    anotherRelayer.address,
                    tokenAddress,
                    someone.address,
                    balanceRelayer,
                    unlockRecipient,
                    transferId
                );

            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(balanceRelayer * 2);
        });

        it("Shouldn't transfer token to zero address or self", async () => {
            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([tokenAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([tokenAddress], [true]);

            await expect(
                proxy
                    .connect(relayer)
                    .transferTokens(
                        tokenAddress,
                        ethers.constants.AddressZero,
                        1,
                        10000000000,
                        unlockRecipient,
                        defaultValidTillBlockHeight
                    )
            ).to.be.revertedWith("Wrong recipient provided");

            await expect(
                proxy
                    .connect(relayer)
                    .transferTokens(
                        tokenAddress,
                        relayer.address,
                        1,
                        10000000000,
                        unlockRecipient,
                        defaultValidTillBlockHeight
                    )
            ).to.be.revertedWith("Wrong recipient provided");
        });

        it("Shouldn't process the transfer with zero amount specified", async () => {
            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([tokenAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([tokenAddress], [true]);

            await expect(
                proxy
                    .connect(relayer)
                    .transferTokens(tokenAddress, someone.address, 1, 0, unlockRecipient, defaultValidTillBlockHeight)
            ).to.be.revertedWith("Wrong amount provided");
        });

        it("Should transfer with ETH", async () => {
            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([relayerEthAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([relayerEthAddress], [true]);

            const ethAmount = ethers.utils.parseEther("0.0000001");

            let transferId = getTransferId(relayerEthAddress, user.address, nonce, ethAmount);
            await expect(
                proxy
                    .connect(relayer2)
                    .transferTokens(
                        relayerEthAddress,
                        user.address,
                        nonce,
                        ethAmount,
                        unlockRecipient,
                        defaultValidTillBlockHeight,
                        {
                            value: ethAmount
                        }
                    )
            )
                .to.emit(proxy, "TransferTokens")
                .withArgs(
                    nonce,
                    relayer2.address,
                    relayerEthAddress,
                    user.address,
                    ethAmount,
                    unlockRecipient,
                    transferId
                );
        });

        it("Shouldn't process the same ETH-transfer twice", async () => {
            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([relayerEthAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([relayerEthAddress], [true]);

            const ethAmount = ethers.utils.parseEther("0.0000001");
            let transferId = getTransferId(relayerEthAddress, user.address, nonce, ethAmount);
            await expect(
                proxy
                    .connect(relayer3)
                    .transferTokens(
                        relayerEthAddress,
                        user.address,
                        nonce,
                        ethAmount,
                        unlockRecipient,
                        defaultValidTillBlockHeight,
                        {
                            value: ethAmount
                        }
                    )
            )
                .to.emit(proxy, "TransferTokens")
                .withArgs(
                    nonce,
                    relayer3.address,
                    relayerEthAddress,
                    user.address,
                    ethAmount,
                    unlockRecipient,
                    transferId
                );

            await expect(
                proxy
                    .connect(relayer3)
                    .transferTokens(
                        relayerEthAddress,
                        user.address,
                        nonce,
                        ethAmount,
                        unlockRecipient,
                        defaultValidTillBlockHeight,
                        {
                            value: ethAmount
                        }
                    )
            ).to.be.revertedWith("This transaction has already been processed!");
        });

        it("Shouldn't process ETH-transfer with undesirable amount", async () => {
            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([relayerEthAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([relayerEthAddress], [true]);

            const ethAmountActual = ethers.utils.parseEther("0.0000001");
            const ethAmountExpected = ethers.utils.parseEther("0.0000002");
            await expect(
                proxy
                    .connect(relayer3)
                    .transferTokens(
                        relayerEthAddress,
                        user.address,
                        nonce,
                        ethAmountExpected,
                        unlockRecipient,
                        defaultValidTillBlockHeight,
                        {
                            value: ethAmountActual
                        }
                    )
            ).to.be.revertedWith("Wrong ethers amount provided");
        });

        it("Shouldn't process transfer with erc20 and ETH both", async () => {
            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([tokenAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([tokenAddress], [true]);

            let relayerBalance = await tokenInstance.balanceOf(relayer.address);
            await tokenInstance.connect(relayer).approve(proxy.address, relayerBalance);

            let transferPart = relayerBalance - 100;

            const ethAmount = ethers.utils.parseEther("0.0000001");
            await expect(
                proxy
                    .connect(relayer)
                    .transferTokens(
                        tokenAddress,
                        someone.address,
                        nonce,
                        transferPart,
                        unlockRecipient,
                        defaultValidTillBlockHeight,
                        {
                            value: ethAmount
                        }
                    )
            ).to.be.revertedWith("Ethers not accepted for ERC-20 transfers");
            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(0);
            expect(await tokenInstance.balanceOf(relayer.address)).to.be.equal(transferPart + 100);
        });
    });

    describe("Admin functionality", () => {
        it("Only admin can withdraw the stuck tokens", async () => {
            let balanceSomeoneWithTokens = await tokenInstance.balanceOf(someoneWithTokens.address);
            await tokenInstance.connect(someoneWithTokens).transfer(proxy.address, balanceSomeoneWithTokens);

            expect(await tokenInstance.balanceOf(someoneWithTokens.address)).to.be.equal(0);

            await expect(proxy.connect(someone).withdrawStuckTokens(tokenAddress)).to.be.reverted;

            let bridgeBalanceBefore = await tokenInstance.balanceOf(proxy.address);
            let ownerBalanceBefore = await tokenInstance.balanceOf(owner.address);
            await proxy.connect(owner).withdrawStuckTokens(tokenAddress);

            expect(await tokenInstance.balanceOf(owner.address)).to.be.equal(
                bridgeBalanceBefore.add(ownerBalanceBefore)
            );
        });

        it("Only pausable admin can pause contract", async () => {
            await expect(proxy.connect(someone).pause()).to.be.reverted;
            await expect(proxy.connect(pausableAdmin).pause()).to.emit(proxy, "Paused").withArgs(pausableAdmin.address);
        });

        it("Only unpausable admin can unpause contract", async () => {
            await expect(proxy.connect(pausableAdmin).pause()).to.emit(proxy, "Paused").withArgs(pausableAdmin.address);
            await expect(proxy.connect(someone).unPause()).to.be.reverted;
            await expect(proxy.connect(unpausableAdmin).unPause())
                .to.emit(proxy, "Unpaused")
                .withArgs(unpausableAdmin.address);
        });

        it("Only admin and whitelisting admin can whitelisted tokens", async () => {
            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([tokenAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([tokenAddress], [true]);

            await expect(proxy.connect(whitelistingAdmin).setWhitelistedTokens([tokenAddress], [false]))
                .to.emit(proxy, "SetTokens")
                .withArgs([tokenAddress], [false]);

            await expect(proxy.connect(owner).setWhitelistedTokens([tokenAddress], [true]))
                .to.emit(proxy, "SetTokens")
                .withArgs([tokenAddress], [true]);
        });

        it("Only admin and whitelisting admin can add/remove token to/from white list", async () => {
            await expect(proxy.connect(whitelistingAdmin).addTokenToWhitelist(tokenAddress))
                .to.emit(proxy, "AddTokenToWhitelist")
                .withArgs(tokenAddress);
            await expect(proxy.connect(whitelistingAdmin).removeTokenFromWhitelist(tokenAddress))
                .to.emit(proxy, "RemoveTokenFromWhitelist")
                .withArgs(tokenAddress);

            await expect(proxy.connect(owner).addTokenToWhitelist(tokenAddress))
                .to.emit(proxy, "AddTokenToWhitelist")
                .withArgs(tokenAddress);
            await expect(proxy.connect(owner).addTokenToWhitelist(tokenAddress)).to.be.revertedWith(
                "Token already whitelisted!"
            );

            await expect(proxy.connect(owner).removeTokenFromWhitelist(tokenAddress))
                .to.emit(proxy, "RemoveTokenFromWhitelist")
                .withArgs(tokenAddress);
            await expect(proxy.connect(owner).removeTokenFromWhitelist(tokenAddress)).to.be.revertedWith(
                "Token not whitelisted!"
            );

            await expect(proxy.connect(someone).removeTokenFromWhitelist(tokenAddress)).to.be.reverted;
            await expect(proxy.connect(someone).addTokenToWhitelist(tokenAddress)).to.be.reverted;
        });
    });
});
