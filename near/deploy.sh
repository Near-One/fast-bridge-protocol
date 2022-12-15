# login
#near login

# build & test
./build.sh && ./test.sh

MASTER_ACCOUNT="<YOUR_ACCOUNT>"
BRIDGE_ACCOUNT=transfer.$MASTER_ACCOUNT
TOKEN_ACCOUNT=token.$MASTER_ACCOUNT
MIN_TIME_LOCK_NS=3600000000000

# clean up previuos deployment
near delete $BRIDGE_ACCOUNT $MASTER_ACCOUNT
near delete $TOKEN_ACCOUNT $MASTER_ACCOUNT

# create corresponding accounts
near create-account $BRIDGE_ACCOUNT --masterAccount $MASTER_ACCOUNT --initialBalance 20
near create-account $TOKEN_ACCOUNT --masterAccount $MASTER_ACCOUNT --initialBalance 10

# redeploy contracts
near deploy $BRIDGE_ACCOUNT --wasmFile ./res/bridge.wasm --initGas   300000000000000 --initFunction 'new' --initArgs '{"eth_bridge_contract": "6b175474e89094c44da98b954eedeac495271d0f", "lock_time_min": "1h", "lock_time_max": "24h"}'
near deploy $TOKEN_ACCOUNT --wasmFile ./res/mock_token.wasm --initFunction 'new_default_meta' --initArgs '{"owner_id": "'"$MASTER_ACCOUNT"'", "name": "Wrapped Near", "symbol": "WNEAR", "total_supply": "1"}'


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
near call $BRIDGE_ACCOUNT init_transfer "{\"transfer_message\":{\"chain_id\":5,\"valid_till\":"$valid_till",\"transfer\":{\"token_near\":"\"$TOKEN_ACCOUNT\"",\"token_eth\":[178,215,92,90,20,42,104,189,164,56,230,163,24,199,251,178,36,47,150,147],\"amount\":\"9000000000000000000000000\"},\"fee\":{\"token\":"\"$TOKEN_ACCOUNT\"",\"amount\":\"1000000000000000000000000\"},\"recipient\":[42,35,224,250,58,254,119,175,245,220,108,106,0,126,58,16,193,69,6,51]}}" --account-id $MASTER_ACCOUNT --gas 300000000000000
