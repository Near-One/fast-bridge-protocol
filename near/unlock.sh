BRIDGE_ACCOUNT=fastbridge.testnet
UNLOCK_ACCOUNT=""
TRANSFER_NONCE="1"
RAINBOW_BRIDGE_INDEX_JS_PATH="$HOME/aurora/rainbow-bridge/cli/index.js"
ETH_CONTRACT_ADDRESS="0x00763f30eEB0eEF506907e18f2a6ceC2DAb30Df8"
BLOCK_NUMBER=8610647
ETH_RPC_URL="https://goerli.infura.io/v3/$RPC_KEY"


TRANSFER_MSG=$(near view $BRIDGE_ACCOUNT get_pending_transfer '{"id": "'"$TRANSFER_NONCE"'"}' | tail -n 12 | head -n 11)
STORAGE_KEY="0x"$(cargo run --manifest-path utils/Cargo.toml -- get-transfer-storage-key -n $TRANSFER_NONCE -m "$TRANSFER_MSG" | tail -n 1)
JSON_PROOF=$($RAINBOW_BRIDGE_INDEX_JS_PATH eth-to-near-find-storage-proof $ETH_CONTRACT_ADDRESS $STORAGE_KEY $BLOCK_NUMBER --eth-node-url $ETH_RPC_URL)
ENCODED_UNLOCK_ARGS=$(cargo run --manifest-path utils/Cargo.toml -- encode-unlock-proof -n $TRANSFER_NONCE -p $JSON_PROOF | tail -n 1)
near call $BRIDGE_ACCOUNT unlock --base64 $ENCODED_UNLOCK_ARGS --account-id $UNLOCK_ACCOUNT --depositYocto 1 --gas 300000000000000
