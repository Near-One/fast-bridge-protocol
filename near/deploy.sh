# login
# near login

# build & test
./build.sh && ./test.sh

# clean up previuos deployment
near delete transfer.spectrebridge.testnet spectrebridge.testnet
near delete token.spectrebridge.testnet spectrebridge.testnet

# create corresponding accoutns
near create-account transfer.spectrebridge.testnet --masterAccount spectrebridge.testnet --initialBalance 10
near create-account token.spectrebridge.testnet --masterAccount spectrebridge.testnet --initialBalance 10

# redeploy contracts
near deploy transfer.spectrebridge.testnet --wasmFile ./res/bridge.wasm 
near deploy token.spectrebridge.testnet --wasmFile ./res/mock_token.wasm --initFunction 'new_default_meta' --initArgs '{"owner_id": "spectrebridge.testnet", "name": "Wrapped Near", "symbol": "WNEAR", "total_supply": "1000000000"}'
