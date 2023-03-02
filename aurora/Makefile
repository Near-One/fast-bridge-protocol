NETWORK=testnet_aurora
AURORA_FAST_BRIDGE_ADDRESS=0x4145a1736E94Ffe194b957329D8e4A01942fC0b9

deploy:
	yarn hardhat run scripts/deploy.js --network $(NETWORK)

tokens_registration:
	yarn hardhat tokens_registration --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

withdraw:
	yarn hardhat withdraw --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)