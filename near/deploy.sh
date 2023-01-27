# login
#near login

# build & test
./build.sh && ./test.sh

MASTER_ACCOUNT="<YOUR_ACCOUNT>"
BRIDGE_ACCOUNT=fast-bridge.$MASTER_ACCOUNT
TOKEN_ACCOUNT=token.$MASTER_ACCOUNT
MIN_TIME_LOCK_NS=3600000000000
export NEAR_ENV=testnet

# clean up previuos deployment
near delete $BRIDGE_ACCOUNT $MASTER_ACCOUNT
near delete $TOKEN_ACCOUNT $MASTER_ACCOUNT

# create corresponding accounts
near create-account $BRIDGE_ACCOUNT --masterAccount $MASTER_ACCOUNT --initialBalance 20
near create-account $TOKEN_ACCOUNT --masterAccount $MASTER_ACCOUNT --initialBalance 10

# redeploy contracts
near deploy $BRIDGE_ACCOUNT --wasmFile ./res/bridge.wasm --initGas   300000000000000 --initFunction 'new' --initArgs '{"eth_bridge_contract": "23244a6c91e66526e4a0959B2457a702aE661Acf", "prover_account": "prover.goerli.testnet", "eth_client_account": "client-eth2.goerli.testnet", "lock_time_min": "1h", "lock_time_max": "24h", "eth_block_time": 12000000000}'
near deploy $TOKEN_ACCOUNT --wasmFile ./res/mock_token.wasm --initFunction 'new_default_meta' --initArgs '{"owner_id": "'"$MASTER_ACCOUNT"'", "name": "Wrapped Near", "symbol": "WNEAR", "total_supply": "1"}'

# grant roles
near call $BRIDGE_ACCOUNT acl_grant_role '{"role": "WhitelistManager", "account_id": "'"$MASTER_ACCOUNT"'"}' --accountId $BRIDGE_ACCOUNT
near call $BRIDGE_ACCOUNT acl_grant_role '{"role": "ConfigManager", "account_id": "'"$MASTER_ACCOUNT"'"}' --accountId $BRIDGE_ACCOUNT

# add the token to whitelist
near call $BRIDGE_ACCOUNT set_token_whitelist_mode '{"token": "'"$TOKEN_ACCOUNT"'", "mode": "CheckToken"}' --accountId $MASTER_ACCOUNT

near call $TOKEN_ACCOUNT mint '{"account_id": "'"$MASTER_ACCOUNT"'", "amount": "1000000000000000000000000000"}' --accountId $MASTER_ACCOUNT

# fund $BRIDGE_ACCOUNT
near call $TOKEN_ACCOUNT storage_deposit '{"account_id": "'"$BRIDGE_ACCOUNT"'"}' --accountId $MASTER_ACCOUNT --amount 0.25

# add mock data
# near call $BRIDGE_ACCOUNT ft_on_transfer '{"token_id": "'"$TOKEN_ACCOUNT"'", "amount": 10000000000000000000000000}' --account-id $MASTER_ACCOUNT
near call $TOKEN_ACCOUNT ft_transfer_call '{"receiver_id": "'"$BRIDGE_ACCOUNT"'", "amount": "10000000000000000000000000", "msg": ""}' --account-id $MASTER_ACCOUNT --depositYocto 1 --gas 300000000000000

# get initialized lock duration
near view $BRIDGE_ACCOUNT get_lock_duration

sec_to_ns=1000000000
current_timestamp=$(($(date +%s)*$sec_to_ns))
valid_till=$((current_timestamp + MIN_TIME_LOCK_NS + 15000000000))

# valid_till is current timestamp + min time lock in nanoseconds + extra 15 sec

TRANSFER_MSG="{\"valid_till\":"$valid_till",\"transfer\":{\"token_near\":"\"$TOKEN_ACCOUNT\"",\"token_eth\":\"b2d75c5a142a68bda438e6a318c7fbb2242f9693\",\"amount\":\"90\"},\"fee\":{\"token\":"\"$TOKEN_ACCOUNT\"",\"amount\":\"10\"},\"recipient\":\"2a23e0fa3afe77aff5dc6c6a007e3a10c1450633\"}"
ENCODED_MSG=$(cargo run --manifest-path utiles/Cargo.toml -- encode-transfer-msg -m $TRANSFER_MSG | tail -n 1)

# Transfer and init in one transaction
near call $TOKEN_ACCOUNT ft_transfer_call '{"receiver_id": "'"$BRIDGE_ACCOUNT"'", "amount": "100", "msg": '"$ENCODED_MSG"'}' --account-id $MASTER_ACCOUNT --depositYocto 1 --gas 300000000000000

# Transfer and init in two transactions
near call $TOKEN_ACCOUNT ft_transfer_call '{"receiver_id": "'"$BRIDGE_ACCOUNT"'", "amount": "100", "msg": ""}' --account-id $MASTER_ACCOUNT --depositYocto 1 --gas 300000000000000
near call $BRIDGE_ACCOUNT init_transfer "{\"msg\": $ENCODED_MSG}" --account-id $MASTER_ACCOUNT --gas 300000000000000
