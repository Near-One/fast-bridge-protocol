import pytest
import brownie 
from brownie import accounts
from brownie import EthErc20FastBridge


@pytest.fixture
def someone(accounts):
    return accounts.add()

@pytest.fixture
def owner(accounts):
    return accounts[0]

@pytest.fixture
def bridge(owner, EthErc20FastBridge): 
    bridge = EthErc20FastBridge.deploy({'from': owner})
    return bridge

