# NEAR-FastBridge

## How to generate unlock-proof for `unlock` method :-

- To generate proofs one need to call RPC method `eth_getProof` [check-here](https://eips.ethereum.org/EIPS/eip-1186).
- Pre-requisites before calling `eth_getProof` :
  - DATA, 20 Bytes - address of the account.
  - ARRAY, 32 Bytes - array of storage-keys which should be proofed and  included. See eth_getStorageAt
  - QUANTITY|TAG - integer block number, or the string "latest" or "earliest"


## About Parameters of `unlock()` method :-

- ### Proof:-
  - `header_data: Vec<u8>` : Rlp-Serilized Header data from RPC call to `eth_getBlockByNumber`  [check here](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getblockbynumber)
  - `account_proof: Vec<Vec<u8>>`: Buffer data of account-proof from `eth_getProof` method call response.
  - `account_data: Vec<u8>`: encoded account state made-up of `{nonce, balance, storageHash, codeHash}`
  - `storage_proof: Vec<Vec<u8>>`: Buffer data of `storage-proof` for above `storage_key` from `eth_getProof` method call response.

- ### nonce:-
  - value of `nonce` when user made transfer at NEAR side.  