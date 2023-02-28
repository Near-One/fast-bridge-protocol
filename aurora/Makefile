NETWORK=testnet_aurora
AURORA_FAST_BRIDGE_ADDRESS=0x84C9fD60ED96c6D980374e5A301d39C131ec879A

deploy:
	yarn hardhat run scripts/deploy.js --network $(NETWORK)

tokens_registration:
	yarn hardhat tokens_registration --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)