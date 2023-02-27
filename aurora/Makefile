NETWORK=testnet_aurora
AURORA_FAST_BRIDGE_ADDRESS=0x575Ae1d398e37aF5a987F165a359938a4310D05D

deploy:
	yarn hardhat run scripts/deploy.js --network $(NETWORK)

init_near_contract:
	yarn hardhat init_near_contract --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)