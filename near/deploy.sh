# login
#near login

# build & test
./build.sh && ./test.sh

# clean up previuos deployment
near delete transfer.spectrebridge.testnet spectrebridge.testnet
near delete token.spectrebridge.testnet spectrebridge.testnet

# create corresponding accoutns
near create-account transfer.spectrebridge.testnet --masterAccount spectrebridge.testnet --initialBalance 20
near create-account token.spectrebridge.testnet --masterAccount spectrebridge.testnet --initialBalance 10

# redeploy contracts
near deploy transfer.spectrebridge.testnet --wasmFile ./res/bridge.wasm
near deploy token.spectrebridge.testnet --wasmFile ./res/mock_token.wasm --initFunction 'new_default_meta' --initArgs '{"owner_id": "spectrebridge.testnet", "name": "Wrapped Near", "symbol": "WNEAR", "total_supply": "1"}'


near call token.spectrebridge.testnet mint '{"account_id": "spectrebridge.testnet", "amount": "1000000000000000000000000000"}' --accountId spectrebridge.testnet

# fund transfer.spectrebridge.testnet
near call token.spectrebridge.testnet storage_deposit '{"account_id": "transfer.spectrebridge.testnet"}' --accountId spectrebridge.testnet --amount 0.25

# add mock data
# near call transfer.spectrebridge.testnet ft_on_transfer '{"token_id": "token.spectrebridge.testnet", "amount": 10000000000000000000000000}' --account-id spectrebridge.testnet
near call token.spectrebridge.testnet ft_transfer_call '{"receiver_id": "transfer.spectrebridge.testnet", "amount": "10000000000000000000000000", "msg": ""}' --account-id spectrebridge.testnet --depositYocto 1 --gas 300000000000000

# valid_till must be current timestamp + min time lock in nanoseconds
near call transfer.spectrebridge.testnet lock '{"msg": "{\"chain_id\":5, \"valid_till\": 1656491326879389137,\"transfer\":{\"token_near\":\"token.spectrebridge.testnet\",\"token_eth\":[ 178,  215,  92,  90,  20,  42,  104,  189,  164,  56,  230,  163,  24,  199,  251,  178,  36,  47,  150,  147 ],\"amount\":\"9000000000000000000000000\"},\"fee\":{\"token\":\"token.spectrebridge.testnet\",\"amount\":\"1000000000000000000000000\"},\"recipient\":[ 42,  35,  224,  250,  58,  254,  119,  175,  245,  220,  108,  106,  0,  126,  58,  16,  193,  69,  6,  51 ]}"}' --account-id spectrebridge.testnet --gas 300000000000000