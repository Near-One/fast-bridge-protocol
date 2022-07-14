# spectrebridge-near

## Build
### Requirements
* Ubunutu 20.04 or later
* build-essential package
* cargo 1.60.0+
* rustc 1.60.0+ with `wasm32-unknown-unknown` traget
* near cli 3.4.0+

### Build & Test
To build and test contracts run following snippet

```
./build.sh
./test.sh
```

### Configuring contract
Before deployment you may want to set following parameters
* eth_bridge_contract - ethereum bridge countrerpart address (default is null address)
* lock_time_min - minimum time at which user tokens are locked (default is 1 hour)
* lock_time_max - maximum time at which user tokens are locked (default is 24 hour)

### Deploy
Deployment is configured only for `testnet` testnet and could be done with the following scirpt

```
./deploy.sh
```

deployment is done via `spectrebridge.testnet` master account to the following subaccounts:
* Bridge: transfer.spectrebridge.testnet
* Mock NEP141 token: token.spectrebridge.testnet
