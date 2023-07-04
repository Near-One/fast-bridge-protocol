NETWORK=testnet_aurora
AURORA_FAST_BRIDGE_ADDRESS=0x9fb6Fb03108a6A1C474F55Efc57E88CbfD4Cc807

# To generate hex borsh representation of init_token_transfer_arg you can use the script from: `../near/utils`
# Go to the `../near/utils/` folder and run `cargo run -- encode-transfer-msg -m <JSON_MESSAGE>`
# where <JSON_MESSAGE> is a init_token_transfer_arg in json format. More details in README.md in `../near/utils`
# You will need the output in line which started with `Encoded message(hex):`
INIT_TOKEN_TRANSFER_ARG="0xc5b125d33b0e48173f000000303738363563366538376239663730323535333737653032346163653636333063316561613337662e666163746f72792e676f65726c692e746573746e657407865c6e87b9f70255377e024ace6630c1eaa37fa08601000000000000000000000000003f000000303738363563366538376239663730323535333737653032346163653636333063316561613337662e666163746f72792e676f65726c692e746573746e6574a08601000000000000000000000000001c6a38ac14e5fdd4f378192fad90db7025f1db6700"

deploy:
	yarn hardhat run scripts/deploy.js --network $(NETWORK)

tokens_registration:
	yarn hardhat tokens_registration --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

withdraw:
	yarn hardhat withdraw --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --init-token-transfer-arg $(INIT_TOKEN_TRANSFER_ARG)

test:
	yarn hardhat test --network testnet_aurora