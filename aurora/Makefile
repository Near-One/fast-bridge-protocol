AURORA_FAST_BRIDGE_ADDRESS=0xba120F3757a2C75eA4AcC3fC3c9819AC378A10E0

# To generate hex borsh representation of init_token_transfer_arg you can use the script from: `../near/utils`
# Go to the `../near/utils/` folder and run `cargo run -- encode-transfer-msg -m <JSON_MESSAGE>`
# where <JSON_MESSAGE> is a init_token_transfer_arg in json format. More details in README.md in `../near/utils`
# You will need the output in line which started with `Encoded message(hex):`

NONCE=47
VALID_TILL_BLOCK_HIEGHT=9587534

NETWORK=testnet_aurora
NEAR_TOKEN_ACCOUNT_ID="07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet"
ETH_TOKEN_ADDRESS="0x07865c6E87B9F70255377e024ace6630C1Eaa37F"
AURORA_TOKEN_ADDRESS=0x901fb725c106E182614105335ad0E230c91B67C8
TRANSFER_TOKEN_AMOUNT=200
CONFIG_NAME="aurora-testnet"
WITHDRAW_ADDRESS=

deploy:
	yarn hardhat deploy --aurora-fast-bridge-config-name $(CONFIG_NAME) --network $(NETWORK)

upgrade:
	yarn hardhat upgrade --aurora-fast-bridge-config-name $(CONFIG_NAME) --proxy $(AURORA_FAST_BRIDGE_ADDRESS) --network $(NETWORK)

register_token:
	yarn hardhat register_token --network $(NETWORK)  --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID)
	
storage_deposit:
	yarn hardhat storage_deposit --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID) --aurora-token-address $(AURORA_TOKEN_ADDRESS) --eth-token-address $(ETH_TOKEN_ADDRESS)

unlock:
	yarn hardhat unlock --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --nonce $(NONCE) --eth-token-address $(ETH_TOKEN_ADDRESS) --valid-till-block-height $(VALID_TILL_BLOCK_HIEGHT)

fast_bridge_withdraw_on_near:
	yarn hardhat fast_bridge_withdraw_on_near --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID) --token-amount $(TRANSFER_TOKEN_AMOUNT)

withdraw_from_implicit_near_account:
	yarn hardhat withdraw_from_implicit_near_account --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID) --recipient-address $(WITHDRAW_ADDRESS)

get_implicit_near_account_id:
	yarn hardhat get_implicit_near_account_id --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)
	
get_token_aurora_address:
	yarn hardhat get_token_aurora_address --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID)

get_balance: 
	yarn hardhat get_balance --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID)

set_whitelist_mode_for_users:
	yarn hardhat set_whitelist_mode_for_users --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID)

disable_whitelist_mode:
	yarn hardhat set_whitelist_mode --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --enabled false

enable_whitelist_mode:
	yarn hardhat set_whitelist_mode --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --enabled true

is_user_whitelisted:
	yarn hardhat is_user_whitelisted --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address  $(AURORA_FAST_BRIDGE_ADDRESS) --network $(NETWORK)

is_storage_registered:
	yarn hardhat is_storage_registered --network $(NETWORK) --aurora-fast-bridge-config-name $(CONFIG_NAME) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID)

fmt:
	yarn prettier contracts/src/AuroraErc20FastBridge.sol --write --plugin=prettier-plugin-solidity

test:
	yarn hardhat test --network testnet_aurora

verify:
	yarn hardhat verify --network $(NETWORK) $(AURORA_FAST_BRIDGE_ADDRESS)
