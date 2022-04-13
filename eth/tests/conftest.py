import pytest
import brownie 
from pathlib import Path
from scripts.deploy_testnet.deploy_helpers import encode_function_data
from brownie import accounts, chain, project, config, Contract
from brownie import EthErc20FastBridge


ERC1967Proxy = project.load(
    Path.home() / ".brownie" / "packages" / config["dependencies"][0]
).ERC1967Proxy


@pytest.fixture(scope="function", autouse=True)
def takeSnapshot():
    chain.snapshot()
    yield
    chain.revert()

@pytest.fixture
def someone(accounts):
    return accounts[9]

@pytest.fixture
def owner(accounts):
    return accounts[0]

@pytest.fixture
def weth(interface):
    yield interface.ERC20('0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2')

@pytest.fixture
def uniswap(interface):
    yield interface.IUniswapV2Router01("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")

@pytest.fixture
def token(interface):
    return interface.ERC20('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48')

@pytest.fixture
def relayer(accounts, token, uniswap, weth):
    relayer = accounts[1]

    # Exchange ETH for token on Uniswap.
    token.approve(uniswap, 2 ** 256 -1, {'from': relayer})
    uniswap.swapExactETHForTokens(
        0,
        [weth, token],
        relayer,
        chain.time() + 10,
        {"from": relayer, "value": "10 ether"}
    )
    assert token.balanceOf(relayer) > 0

    return relayer

@pytest.fixture
def another_relayer(accounts, token, uniswap, weth, relayer):
    another_relayer = accounts[2]

    # Exchange ETH for token on Uniswap.
    token.approve(uniswap, 2 ** 256 -1, {'from': another_relayer})
    uniswap.swapExactETHForTokens(
        0,
        [weth, token],
        another_relayer,
        chain.time() + 10,
        {"from": another_relayer, "value": "100 ether"}
    )
    assert token.balanceOf(another_relayer) > token.balanceOf(relayer) and token.balanceOf(another_relayer) > 0

    return another_relayer

@pytest.fixture
def someone_with_tokens(accounts, token, relayer):
    acc = accounts.add()
    token.transfer(acc, token.balanceOf(relayer), {'from': relayer})

    return acc

@pytest.fixture
def bridge(owner, EthErc20FastBridge): 
    bridge = EthErc20FastBridge.deploy({'from': owner})

    bridge_encoded_initializer_function = encode_function_data(
        bridge.initialize, 
        [], 
        []
    )
    proxy = ERC1967Proxy.deploy(
        bridge.address,
        bridge_encoded_initializer_function, 
        {"from": owner}
    )
    proxy_box = Contract.from_abi("EthErc20FastBridge", proxy.address, EthErc20FastBridge.abi)
    return proxy_box

