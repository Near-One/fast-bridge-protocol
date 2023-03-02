# Aurora Erc20 Fast Bridge
## Setup
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