# spectre-bridge-protocol

Spectre bridge is one-way semi-decentralized bridge created to speed up transfers from Near to Ethereum.

## How it works
1) User initiate unique transfer `{nonce, amount, {fee_token, fee_amount}, recipient, valid_till}` that is valid for some reasonably small period of time. That locks `amount` and `fee_amount` on NearErc20FastBridge contract
2) NearErc20FastBridge contract generates `SpectreBridgeTransferEvent` with the following metadata `{nonce, chain_id, valid_till, transfer: {token_near, token_eth, amount}, fee: {token, amount}, recipient}`
3) LP-relayer receives an event and makes a decision to process or not the transfer
4) LP-Relayer transfers `amount` to `recipient` on Ethereum side via EthErc20FastBridge on Ethereum side
5) Light-client Relayer submits the block to `EthOnNearClient` contract and after the needed amount of confirmations is done, the LP-relayer is ready to receive the `amount` and `fee` for the fast bridge transfer.
6) LP-relayer provides proof for the `NearErc20FastBridge` that exact transfer was done on Ethereum via `EthErc20FastBridge` and receives the `amount` and `fee` for the transfer.

![Rainbow bridge flow - User Money-Out via Trustless Centralized LP-Relayer Flow](https://user-images.githubusercontent.com/91728093/178957579-66c43881-561d-4151-be9f-426928901965.jpg)

## Build
The bridge consist of three main components:
* Bridge node
* Near contracts
* Ethereum contracts

Current repo is for ethereum and near contracts, node is located [here](https://github.com/spectrebridge/spectre-bridge-service)

### Ethereum
Described in the corresponding [README](eth/README.md)

### Near
Described in the corresponding [README](near/README.md)
