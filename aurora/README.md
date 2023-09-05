# Aurora Erc20 Fast Bridge
## Setup
Fetch git submodules
```bash
$ git submodule init
$ git submodule update
```

Install hardhat
```bash
$ yarn add hardhat
```
Save to `.env` file `AURORA_PRIVATE_KEY` variable with the aurora private key in hex format (without `0x`). That private key will be used for the contract deployment and for the interaction with the contract using different available scripts.

## Run contract
Deploy contract
```bash
$ make deploy
```
After deploying, you will get the address of the newly created contract. Save it to the `AURORA_FAST_BRIDGE_ADDRESS` variable in Makefile. Also, please specify the values of `NETWORK`, `SILO` variables in the Makefile prior to the proceeding.


For registration USDC tokens and init contract on Near run:
```bash
$ make tokens_registration
```

Before running the `init_token_transfer` first you should set up the `INIT_TOKEN_TRANSFER_ARG` in Makefile.
It is the arguments for init_transfer in Near FastBridge contract, in Borsh format but in `hex` string, not in `base64` 

To initialize the token transfer from Aurora to Ethereum, run:
```bash
$ make init_token_transfer
``` 

To withdraw tokens in case of error during transfer initialization, run:
```bash
$ make withdraw
```

### Unlock tokens
If the tokens weren't transferred to Ethereum after `valid_till` timestamp is passed, you can
unlock your tokens on the Aurora side.

First, you need to figure out the `nonce` of your `init_token_transfer` transaction. You
can find it in logs in Near Explorer, for example, in the transaction
for Fast Bridge contracts on the Near side or for the corresponding
implicit NEAR account ID for this `AuroraErc20FastBridge` contract.

Next, run
```bash
$ make unlock NONCE=YOUR_INIT_TRANSFER_NONCE
```
This method unlocks tokens on the Near side and increases the Aurora user's balance.


To withdraw already unlocked tokens on the Near side for the contract, run:
```bash
$ make withdraw_from_near
```

And finally, to withdraw tokens on the Aurora side to the Aurora user, run:
```bash
$ make withdraw
```

The tokens unlock is complete!

# Tests
For running tests, you will need:
* set up the env variable `MASTER_ACCOUNT` with your Near account on Testnet. You should have a private key saved locally in `~/.near-credentials/testnet/`
* set up the env variable `AURORA_PRIVATE_KEY` with your aurora private key for Testnet.
* `MASTER_ACCOUNT` should have at least 4.25 NEAR tokens.
* Your Aurora account should have at least 2.125 wNEAR, 1 USDC, and 0.01 AuroraETH.
* `eth-object` lib is used in tests. You will need to make sure, that you have the correct library version. `node_modules/eth-object/src/header.js` should contain `withdrawalsRoot` field.
* Test takes ~20 minutes.

The command to run a test: 
```bash
yarn hardhat test --network testnet_aurora
```

## Formatting
To apply formatting for Solidity code run:
```bash
yarn prettier contracts/src/AuroraErc20FastBridge.sol --write --plugin=prettier-plugin-solidity
```

File with formatting rules: `.prettierrc.json`