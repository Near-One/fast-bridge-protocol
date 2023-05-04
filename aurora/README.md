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