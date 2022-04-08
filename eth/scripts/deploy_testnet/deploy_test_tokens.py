from brownie import *
import json
import os
from dotenv import load_dotenv, find_dotenv


def main():
    load_dotenv(find_dotenv())
    # Opening json

    print(f"You are using the '{network.show_active()}' network")
    if (network.show_active() == 'development'):
        deployer = accounts[0]
    else:
        deployer = accounts.add(os.getenv("DEPLOYER_PRIVATE_KEY"))

    print(f"You are using: 'deployer' [{deployer.address}]")

    # Decimals are equal to mainnet.
    test_USDC = deployer.deploy(TestToken, 6, "TEST_USDC", "TUSDC", publish_source=True)
    test_WBTC = deployer.deploy(TestToken, 8, "TEST_WBTC", "TWBTC", publish_source=True)
    test_WETH = deployer.deploy(TestToken, 18, "TEST_WETH", "TWETH", publish_source=True)
    
    print(f"TEST USDC at {test_USDC}")
    print(f"TEST WBTC at {test_WBTC}")
    print(f"TEST WETH at {test_WETH}")