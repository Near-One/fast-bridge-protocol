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
Save to `.env` file `AURORA_PRIVATE_KEY` variable with the aurora private key which you
can extract from MetaMask.

## Run contract
Deploy contract
```bash
$ make deploy
```
After deploying you will get the contract address. Save it to the `AURORA_FAST_BRIDGE_ADDRESS` variable in Makefile


For registration USDC tokens and init contract on Near run:
```bash
$ make tokens_registration
```

Before running the `init_token_transfer` first you should set up the `INIT_TOKEN_TRANSFER_ARG` in Makefile.
It is the arguments for init_transfer in Near FastBridge contract, in Borsh format but in `hex` string, not in `base64` 

For init token transfer from Aurora to Ethereum run:
```bash
$ make init_token_transfer
``` 

For withdraw tokens in case of error during transfer initialization run:
```bash
$ make withdraw
```

### Unlock tokens
If the tokens weren't transferred to Ethereum after `valid_till` you can
unlock your tokens on the Aurora side.

First, you need to figure out the `nonce` of your `init_token_transfer` transaction. You
can find it in logs in near explorer, for example in transaction
for fast bridge contracts on near or for the corresponding
contract on near for this aurora contract.

Next, run
```bash
$ make unlock NONCE=YOUR_INIT_TRANSFER_NONCE
```
This method unlock tokens on Near side and increase aurora user balance.


For withdraw tokens on Near side for the contract run:
```bash
$ make withdraw_from_near
```

And finally, for withdraw tokens on Aurora side to the Aurora User run:
```bash
$ make withdraw
```

The tokens unlock is complete!

# Tests
For running tests you will need
* set up env variable `MASTER_ACCOUNT` with your near account on testnet. You should have a private key saved locally in `~/.near-credentials/testnet/`
* set up env variable `AURORA_PRIVATE_KEY` with your aurora private key for testnet.
* `MASTER_ACCOUNT` should have at least 4.25 NEAR tokens.
* Your aurora account should have at least 2.125 wNEAR and 1 USDC and 0.01 AuroraETH
* `eth-object` lib is used in tests. You will need make sure, that you have a correct library version. `node_modules/eth-object/src/header.js` should contain `withdrawalsRoot` field.
* Test takes ~20 minutes.

Command for running test: 
```bash
yarn hardhat test --network testnet_aurora
```

## Formatting
For apply formatting for Solidity code run:
```bash
yarn prettier contracts/AuroraErc20FastBridge.sol --write
```

File with formatting rules: `.prettierrs.json`