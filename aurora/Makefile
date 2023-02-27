NETWORK=testnet_aurora
AURORA_FAST_BRIDGE_ADDRESS=0x3188Ed5E0EfD63E002a6059239a12816EeB18d4a

deploy:
	yarn hardhat run scripts/deploy.js --network $(NETWORK)

init_near_contract:
	yarn hardhat init_near_contract --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)