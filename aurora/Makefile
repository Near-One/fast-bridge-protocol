NETWORK=testnet_aurora
AURORA_FAST_BRIDGE_ADDRESS=0x86cf73E22379Db04A2e80e6B0211F2b03c29c419

deploy:
	yarn hardhat run scripts/deploy.js --network $(NETWORK)

init_near_contract:
	yarn hardhat init_near_contract --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)