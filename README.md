# spectre-bridge-protocol

Spectre bridge is one-way semi-decentralized bridge created to speed up transfers from Near to Ethereum.

## How it works
1) User initiate unique transfer `{nonce, amount, {fee_token, fee_amount}, recipient, valid_till}` that is valid for some reasonably small period of time. That locks `amount` and `fee_amount` on NearErc20FastBridge contract
2) NearErc20FastBridge contract generates `SpectreBridgeTransferEvent` with the following metadata `{nonce, valid_till, transfer: {token_near, token_eth, amount}, fee: {token, amount}, recipient}`
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


## EthErc20Bridge scripts
Below given command will help user to deploy and interact with contracts only on the network provided in spectre-bridge-protocol/eth/package.json, to switch network just change network name from that script.

example : to deploy EthErc20FastBridge on hardhat network i.e. mainnet fork change 
`npm run compile-all && npx hardhat run scripts/deployment/deploy-bridge.js --network goerli`
to
`npm run compile-all && npx hardhat run scripts/deployment/deploy-bridge.js --network hardhat`
and run below command.
### Deployment script
run command `yarn run deploy:bridge`

### Deploy and verify
run command `yarn run deploy:verify:bridge`

### Upgrade script
Before upgrading, go to file `spectre-bridge-protocol/eth/scripts/EthErc20FastBridge/upgrade_bridge.js` and update current bridge proxy address at line 7.

run command `yarn run upgrade:bridge`

### Whitelisting
To interact with EthErc20FastBridge whitelisting methods use methods defined in spectre-bridge-protocol/eth/scripts/EthErc20FastBridge/whitelistTokens.js

* To bulk update whitelist status of tokens import and use method `bulkWhitelistStatusUpdate` from above mentioned file with an array of token addresses, an array of their corresponding status and a signer with `WHITELISTING_TOKENS_ADMIN_ROLE` as parameters.

* To whitelist one token import and use method `addTokenToWhitelist` from above mentioned file with a token address and a signer with `WHITELISTING_TOKENS_ADMIN_ROLE` as parameters.

* To remove one token from whitelist use method `removeTokenFromWhitelist` from above mentioned file with tokens address and signer with `WHITELISTING_TOKENS_ADMIN_ROLE` as parameters.

* To check whether a token is whitelisted or not import and use method `isTokenInWhitelist` from above mentioned file with tokens address and signer with `WHITELISTING_TOKENS_ADMIN_ROLE` as parameters.  

### Pause/Unpause transfers
To interact with EthErc20FastBridge pause and unpause methods use methods defined in spectre-bridge-protocol/eth/scripts/EthErc20FastBridge/pause_unPause.js

* To pause transfers import and use `pauseTransfer` method from above mentioned file with a signer with `PAUSABLE_ADMIN_ROLE` as parameter. 

* To unpause transfers import and use `unpauseTransfer` method from above mentioned file with a signer with `UNPAUSABLE_ADMIN_ROLE` as parameter. 