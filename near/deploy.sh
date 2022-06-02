# login
#near login

# build & test
./build.sh && ./test.sh

# clean up previuos deployment
near delete transfer.spectrebridge2.testnet spectrebridge2.testnet
near delete token.spectrebridge2.testnet spectrebridge2.testnet

# create corresponding accoutns
near create-account transfer.spectrebridge2.testnet --masterAccount spectrebridge2.testnet --initialBalance 10
near create-account token.spectrebridge2.testnet --masterAccount spectrebridge2.testnet --initialBalance 10

# redeploy contracts
near deploy transfer.spectrebridge2.testnet --wasmFile ./res/bridge.wasm
near deploy token.spectrebridge2.testnet --wasmFile ./res/mock_token.wasm --initFunction 'new_default_meta' --initArgs '{"owner_id": "spectrebridge2.testnet", "name": "Wrapped Near", "symbol": "WNEAR", "total_supply": "1000000000"}'

# fund transfer.spectrebridge2.testnet
near call token.spectrebridge2.testnet mint '{"account_id": "transfer.spectrebridge2.testnet", "amount": "1000000000"}' --accountId spectrebridge2.testnet

# add mock data
near call transfer.spectrebridge2.testnet add_supported_token '{"token": "token.spectrebridge2.testnet"}'  --account-id transfer.spectrebridge2.testnet
near call transfer.spectrebridge2.testnet ft_on_transfer '{"token_id": "token.spectrebridge2.testnet", "amount": 100}' --account-id transfer.spectrebridge2.testnet
near call transfer.spectrebridge2.testnet lock '{"msg": "{\"valid_till\":1652038871250000000,\"transfer\":{\"token\":\"token.spectrebridge2.testnet\",\"amount\":50},\"fee\":{\"token\":\"token.spectrebridge2.testnet\",\"amount\":50},\"recipient\":\"00005474e89094c44da98b954eedeac495271d0f\"}"}' --account-id transfer.spectrebridge2.testnet
#near call transfer.spectrebridge2.testnet lp_unlock '{}' --account-id transfer.spectrebridge2.testnet --gas 300000000000000