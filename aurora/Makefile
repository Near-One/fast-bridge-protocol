NETWORK=testnet_aurora
AURORA_FAST_BRIDGE_ADDRESS=0x570C9748Aa627D43FAC145674D0C38c44900c06a

deploy:
	yarn hardhat run scripts/deploy.js --network $(NETWORK)

init_near_contract:
	yarn hardhat init_near_contract --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)
