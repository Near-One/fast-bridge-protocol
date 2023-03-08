NETWORK=testnet_aurora
AURORA_FAST_BRIDGE_ADDRESS=0xB20FDbd0139447083e56fC412A7140ee40557005
INIT_TOKEN_TRANSFER_ARG="0x45b3380fd8cb49173f000000303738363563366538376239663730323535333737653032346163653636333063316561613337662e666163746f72792e676f65726c692e746573746e657407865c6e87b9f70255377e024ace6630c1eaa37fa08601000000000000000000000000003f000000303738363563366538376239663730323535333737653032346163653636333063316561613337662e666163746f72792e676f65726c692e746573746e6574a08601000000000000000000000000001c6a38ac14e5fdd4f378192fad90db7025f1db6700011c6a38ac14e5fdd4f378192fad90db7025f1db67"
NONCE=1

deploy:
	yarn hardhat run scripts/deploy.js --network $(NETWORK)

tokens_registration:
	yarn hardhat tokens_registration --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

withdraw:
	yarn hardhat withdraw --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

init_token_transfer:
	yarn hardhat init_token_transfer --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --init-token-transfer-arg $(INIT_TOKEN_TRANSFER_ARG)

unlock:
	yarn hardhat unlock --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS) --nonce $(NONCE)

withdraw_from_near:
	yarn hardhat withdraw_from_near --network $(NETWORK) --fast-bridge-address $(AURORA_FAST_BRIDGE_ADDRESS)

test:
	yarn hardhat test --network testnet_aurora