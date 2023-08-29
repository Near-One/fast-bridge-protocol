AURORA_FAST_BRIDGE_ADDRESS=0xE74FC2656FE07FF4915966BAE0808eBCb665415f

# To generate hex borsh representation of init_token_transfer_arg you can use the script from: `../near/utils`
# Go to the `../near/utils/` folder and run `cargo run -- encode-transfer-msg -m <JSON_MESSAGE>`
# where <JSON_MESSAGE> is a init_token_transfer_arg in json format. More details in README.md in `../near/utils`
# You will need the output in line which started with `Encoded message(hex):`
NONCE=47
VALID_TILL_BLOCK_HIEGHT=9587534

NETWORK=testnet_aurora
NEAR_TOKEN_ADDRESS="07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet"
ETH_TOKEN_ADDRESS="0x07865c6E87B9F70255377e024ace6630C1Eaa37F"
AURORA_TOKEN_ADDRESS=0x901fb725c106E182614105335ad0E230c91B67C8
TRANSFER_TOKEN_AMOUNT=200
SILO="aurora-testnet"

deploy:
	yarn hardhat deploy --silo $(SILO) --network $(NETWORK)

upgrade:
	yarn hardhat upgrade --silo $(SILO) --proxy $(AURORA_FAST_BRIDGE_ADDRESS) --network $(NETWORK)

tokens_registration:
	yarn hardhat tokens_registration --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-address $(NEAR_TOKEN_ADDRESS) --aurora-token-address $(AURORA_TOKEN_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-address $(NEAR_TOKEN_ADDRESS) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --eth-token-address $(ETH_TOKEN_ADDRESS)

unlock:
	yarn hardhat unlock --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --nonce $(NONCE) --eth-token-address $(ETH_TOKEN_ADDRESS) --valid-till-block-height $(VALID_TILL_BLOCK_HIEGHT)

withdraw_from_near:
	yarn hardhat withdraw_from_near --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-address $(NEAR_TOKEN_ADDRESS) --token-amount $(TRANSFER_TOKEN_AMOUNT)

withdraw:
	yarn hardhat withdraw --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-address $(NEAR_TOKEN_ADDRESS)

get_near_account_id:
	yarn hardhat get_near_account_id --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)
	
get_token_aurora_address:
	yarn hardhat get_token_aurora_address --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-address $(NEAR_TOKEN_ADDRESS)

get_balance: 
	yarn hardhat get_balance --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-address $(NEAR_TOKEN_ADDRESS)

test:
	yarn hardhat test --network testnet_aurora
