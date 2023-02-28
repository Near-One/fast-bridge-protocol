NETWORK=testnet_aurora
AURORA_FAST_BRIDGE_ADDRESS=0x9808dd913C871757A37f6F64bC600258c5183d6a

deploy:
	yarn hardhat run scripts/deploy.js --network $(NETWORK)

init_near_contract:
	yarn hardhat init_near_contract --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)