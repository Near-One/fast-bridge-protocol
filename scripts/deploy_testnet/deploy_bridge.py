from brownie import *
import json
import os
from dotenv import load_dotenv, find_dotenv


def main():
    load_dotenv(find_dotenv())
    # Opening json
    f = open('./scripts/deploy_testnet/deploy_info.json')
    data = json.load(f)
    tokens = data["tokens"]
    whitelisted_tokens = data["whitelisted_tokens"]

    print(f"You are using the '{network.show_active()}' network")
    if (network.show_active() == 'development'):
        deployer = accounts[0]
    else:
        deployer = accounts.add(os.getenv("DEPLOYER_PRIVATE_KEY"))

    print(f"You are using: 'deployer' [{deployer.address}]")
    tokens_addresses = list(tokens.values())
    whitelisted_tokens = list(whitelisted_tokens.values())
    bridge = deployer.deploy(EthErc20FastBridge, tokens_addresses, whitelisted_tokens)

    print(f"EthErc20FastBridge at {bridge}")
    f.close()