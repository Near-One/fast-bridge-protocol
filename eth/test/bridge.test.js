const { expect, use } = require("chai");
const { solidity } = require("ethereum-waffle");
const { ethers, upgrades } = require("hardhat");
const { snapshot, time, expectRevert, balance } = require("@openzeppelin/test-helpers");
const ether = require("@openzeppelin/test-helpers/src/ether.js");
const { getImplementationAddress } = require("@openzeppelin/upgrades-core");

use(solidity);

const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const Uniswap = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
const tokenAddress = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

const buyTokenForEth = async (buyer, router, ethAmount, path) => {
    await router.connect(buyer).swapExactETHForTokens(0, path, buyer.address, ethers.constants.MaxUint256, { value: ethAmount });
};

describe("Spectre Bridge", () => {
    let router, tokenInstance, weth;
    let owner, someone, relayer, anotherRelayer, someoneWithTokens;
    let snapshotA;
    let bridge, proxy;

    before(async () => {
        [owner, someone, relayer, anotherRelayer, someoneWithTokens] = await ethers.getSigners();
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
        proxy = await upgrades.deployProxy(bridge, [[], []], { unsafeAllow: ['delegatecall'] });
        await proxy.deployed();
    })

    beforeEach(async () => snapshotA = await snapshot());
    afterEach(async () => await snapshotA.restore());

    describe("Whitelisting", () => {
        const tokensAddresses = [
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "0xB8c77482e45F1F44dE1745F52C74426C631bDD52",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        ]
        const tokensStates = [
            true,
            true,
            false
        ]

        it("Should add tokens to whitelist", async () => {
            await proxy.connect(owner).setWhitelistedTokens(tokensAddresses, tokensStates)

            expect(await proxy.isTokenInWhitelist(tokensAddresses[0])).to.be.true;
            expect(await proxy.isTokenInWhitelist(tokensAddresses[1])).to.be.true;
            expect(await proxy.isTokenInWhitelist(tokensAddresses[2])).to.be.false;
        })

        it("Shouldn't setWhitelistedTokens by someone", async () => {
            await expectRevert.unspecified(proxy.connect(someone).setWhitelistedTokens(tokensAddresses, tokensStates));
        })
    })

    it("Should deploy Bridge with tokens and whitelist states", async () => {
        tokensAddresses = [
            "0xb2d75C5a142A68BDA438e6a318C7FBB2242f9693",
            "0xa1f5A105d73204b45778983038f733d8867fBea0",
            "0x3195D5df0521d2Fcd5b02413E23e4b1219790767"
        ];
        tokensStates = [
            true,
            true,
            false
        ];

        const bridgeV1 = await ethers.getContractFactory("EthErc20FastBridge");
        const proxyV1 = await upgrades.deployProxy(bridgeV1, [tokensAddresses, tokensStates], { unsafeAllow: ['delegatecall'] });
        await proxyV1.deployed();

        expect(await proxyV1.isTokenInWhitelist(tokensAddresses[1])).to.be.true;
        expect(await proxyV1.isTokenInWhitelist(tokensAddresses[2])).to.be.false;

        await proxyV1.connect(owner).setWhitelistedTokens(
            [tokensAddresses[2]],
            [true]
        );
        expect(await proxyV1.isTokenInWhitelist(tokensAddresses[2])).to.be.true;
    })

    describe("Transfer", () => {
        it("Should transfer token", async () => {
            await proxy.connect(owner).setWhitelistedTokens(
                [tokenAddress],
                [true]
            );

            relayerBalance = await tokenInstance.balanceOf(relayer.address);
            await tokenInstance.connect(relayer).approve(
                proxy.address,
                relayerBalance
            );

            let transferPart = relayerBalance - 100;

            await proxy.connect(relayer).transferTokens(
                tokenAddress,
                someone.address,
                11231231,
                transferPart
            );

            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(transferPart);

            await proxy.connect(owner).pause();

            relayerBalanceAfter = tokenInstance.balanceOf(relayer.address);
            await expectRevert(proxy.connect(relayer).transferTokens(tokenAddress, someone.address, 11231232, relayerBalanceAfter), "Pausable: paused");

            await proxy.connect(owner).unPause();

            await proxy.connect(relayer).transferTokens(
                tokenAddress,
                someone.address,
                11231232,
                100
            );

            let transferPart2 = transferPart + 100;
            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(transferPart2);
        })

        it("Shouldn't transfer token via two equal transfers", async () => {
            await proxy.connect(owner).setWhitelistedTokens(
                [tokenAddress],
                [true]
            );

            let balanceRelayer = await tokenInstance.balanceOf(relayer.address);
            await tokenInstance.connect(relayer).approve(
                proxy.address,
                balanceRelayer
            );
            let balanceAnotherRelayer = await tokenInstance.balanceOf(anotherRelayer.address);
            await tokenInstance.connect(anotherRelayer).approve(
                proxy.address,
                balanceAnotherRelayer
            );

            await proxy.connect(anotherRelayer).transferTokens(
                tokenAddress,
                someone.address,
                11231231,
                balanceRelayer
            );

            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(balanceRelayer);

            await expectRevert(proxy.connect(anotherRelayer).transferTokens(
                tokenAddress,
                someone.address,
                11231231,
                balanceRelayer
            ), "This transaction has already been processed!");

            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(balanceRelayer);
        })

        it("Should transfer token via two not equal transfers", async () => {
            await proxy.connect(owner).setWhitelistedTokens(
                [tokenAddress],
                [true],
            );

            let balanceRelayer = await tokenInstance.balanceOf(relayer.address);
            await tokenInstance.connect(relayer).approve(
                proxy.address,
                balanceRelayer
            );

            let balanceAnotherRelayer = await tokenInstance.balanceOf(anotherRelayer.address);
            await tokenInstance.connect(anotherRelayer).approve(
                proxy.address,
                balanceAnotherRelayer
            );

            await proxy.connect(relayer).transferTokens(
                tokenAddress,
                someone.address,
                11231231,
                balanceRelayer
            );

            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(balanceRelayer);
            await proxy.connect(anotherRelayer).transferTokens(
                tokenAddress,
                someone.address,
                11231232,
                balanceRelayer
            );

            expect(await tokenInstance.balanceOf(someone.address)).to.be.equal(balanceRelayer * 2);
        })

        it("Shouldn't transfer token to zero address or self", async () => {
            await proxy.connect(owner).setWhitelistedTokens(
                [tokenAddress],
                [true]
            )

            await expectRevert(proxy.connect(relayer).transferTokens(
                tokenAddress,
                ethers.constants.AddressZero,
                1,
                10000000000
            ), "Wrong recipient provided");

            await expectRevert(proxy.connect(relayer).transferTokens(
                tokenAddress,
                relayer.address,
                1,
                10000000000
            ), "Wrong recipient provided");
        })

        it("Shouldn't transfer zero amount", async () => {
            await proxy.connect(owner).setWhitelistedTokens(
                [tokenAddress],
                [true]
            );

            await expectRevert(proxy.connect(relayer).transferTokens(
                tokenAddress,
                someone.address,
                1,
                0,
            ), "Wrong amount provided");
        })
    })

    it("Should withdraw stuck tokens", async () => {
        let balanceSomeoneWithTokens = await tokenInstance.balanceOf(someoneWithTokens.address);
        await tokenInstance.connect(someoneWithTokens).transfer(
            proxy.address,
            balanceSomeoneWithTokens,
        );

        expect(await tokenInstance.balanceOf(someoneWithTokens.address)).to.be.equal(0);

        await expectRevert.unspecified(proxy.connect(someone).withdrawStuckTokens(tokenAddress));

        let bridgeBalanceBefore = await tokenInstance.balanceOf(proxy.address);
        await proxy.connect(owner).withdrawStuckTokens(tokenAddress);

        expect(await tokenInstance.balanceOf(owner.address)).to.be.equal(bridgeBalanceBefore);
    })

})