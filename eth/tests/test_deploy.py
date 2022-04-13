from brownie import *
import json
import os
from dotenv import load_dotenv, find_dotenv
from scripts.deploy_testnet.deploy_helpers import *
from brownie import project, EthErc20FastBridge
from pathlib import Path


def test_deploy():
    tokens_addresses = [
        "0xb2d75C5a142A68BDA438e6a318C7FBB2242f9693",
        "0xa1f5A105d73204b45778983038f733d8867fBea0",
        "0x3195D5df0521d2Fcd5b02413E23e4b1219790767"   
    ]
    whitelisted_tokens = [
        True,
        True,
        False
    ]

    deployer = accounts[0]
    bridge = deployer.deploy(EthErc20FastBridge)

    bridge_encoded_initializer_function = encode_function_data(
        bridge.initialize, 
        tokens_addresses, 
        whitelisted_tokens
    )
    print(f"EthErc20FastBridge implementation at {bridge}")
    proxy = ERC1967Proxy.deploy(
        bridge.address,
        bridge_encoded_initializer_function, 
        {"from": deployer}
    )
    print(f"EthErc20FastBridge proxy at {proxy}")
    proxy_box = Contract.from_abi("EthErc20FastBridge", proxy.address, EthErc20FastBridge.abi)

    assert proxy_box.isTokenInWhitelist("0xa1f5A105d73204b45778983038f733d8867fBea0")
    
    assert proxy_box.isTokenInWhitelist("0x3195D5df0521d2Fcd5b02413E23e4b1219790767") == False
    proxy_box.setWhitelistedTokens(
        ['0x3195D5df0521d2Fcd5b02413E23e4b1219790767'],
        [True],
        {'from': deployer}
    )
    assert proxy_box.isTokenInWhitelist("0x3195D5df0521d2Fcd5b02413E23e4b1219790767")
    boxv2 = EthErc20FastBridge.deploy({"from": deployer})

    proxy_box.upgradeTo(boxv2.address, {"from": deployer})
    proxy_box = Contract.from_abi("EthErc20FastBridge", proxy.address, EthErc20FastBridge.abi)

    assert proxy_box.isTokenInWhitelist("0x3195D5df0521d2Fcd5b02413E23e4b1219790767")