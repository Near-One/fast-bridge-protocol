NETWORK=testnet_aurora
AURORA_FAST_BRIDGE_ADDRESS=0xDE657f30fF609475E604e9cC1b9F7a296Be5396e

deploy:
	yarn hardhat run scripts/deploy.js --network $(NETWORK)

tokens_registration:
	yarn hardhat tokens_registration --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)