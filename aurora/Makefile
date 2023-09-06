AURORA_FAST_BRIDGE_ADDRESS=0xE74FC2656FE07FF4915966BAE0808eBCb665415f

# To generate hex borsh representation of init_token_transfer_arg you can use the script from: `../near/utils`
# Go to the `../near/utils/` folder and run `cargo run -- encode-transfer-msg -m <JSON_MESSAGE>`
# where <JSON_MESSAGE> is a init_token_transfer_arg in json format. More details in README.md in `../near/utils`
# You will need the output in line which started with `Encoded message(hex):`
INIT_TOKEN_TRANSFER_ARG="0xd534a83ba8814a173f000000303738363563366538376239663730323535333737653032346163653636333063316561613337662e666163746f72792e676f65726c692e746573746e657407865c6e87b9f70255377e024ace6630c1eaa37fa08601000000000000000000000000003f000000303738363563366538376239663730323535333737653032346163653636333063316561613337662e666163746f72792e676f65726c692e746573746e6574a08601000000000000000000000000001c6a38ac14e5fdd4f378192fad90db7025f1db6700011c6a38ac14e5fdd4f378192fad90db7025f1db67"
NONCE=1

NETWORK=testnet_aurora
NEAR_TOKEN_ACCOUNT_ID="07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet"
AURORA_TOKEN_ADDRESS=0x901fb725c106E182614105335ad0E230c91B67C8
TRANSFER_TOKEN_AMOUNT=200000
SILO="aurora-testnet"

deploy:
	yarn hardhat deploy --silo $(SILO) --network $(NETWORK)

upgrade:
	yarn hardhat upgrade --silo $(SILO) --proxy $(AURORA_FAST_BRIDGE_ADDRESS) --network $(NETWORK)

register_token:
	yarn hardhat register_token --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID) --aurora-token-address $(AURORA_TOKEN_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --init-token-transfer-arg $(INIT_TOKEN_TRANSFER_ARG) --aurora-token-address $(AURORA_TOKEN_ADDRESS)

unlock:
	yarn hardhat unlock --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --nonce $(NONCE)

fast_bridge_withdraw_on_near:
	yarn hardhat fast_bridge_withdraw_on_near --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID) --token-amount $(TRANSFER_TOKEN_AMOUNT)

withdraw_from_implicit_near_account:
	yarn hardhat withdraw_from_implicit_near_account --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --near-token-account-id $(NEAR_TOKEN_ACCOUNT_ID)

set_whitelist_mode_for_users:
	yarn hardhat set_whitelist_mode_for_users --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --user-address $(USER_ADDRESS)

disable_whitelist_mode:
	yarn hardhat set_whitelist_mode --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --enabled false

enable_whitelist_mode:
	yarn hardhat set_whitelist_mode --network $(NETWORK) --silo $(SILO) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --enabled true

test:
	yarn hardhat test --network testnet_aurora
