# spectrebridge-solidity

## Build
### Requirements
* Ubunutu 20.04 or later
* python 3.8 or later
* pip3 20.0 or later
* npm 8.13.1+

### Build & Test
To build and test contracts run following snippet

```
npm i
npm run preinstall
npm run test
```

### Deploy
Deployment is configured only for `Goerli` testnet and cound be done with the following scirpt

```
npm run deploy:tokens:goerli
npm run deploy:bridge:goerli
```

This will deploy unverified verision. To verify contracts use brownie.publish_source() or you can verify proxy in Etherscan but put constructor args only with implementation address.

https://abi.hashex.org/

#### Contracts in Goerli
* Proxy: 0xbC685C003884c394eBB5F9235a1DBe9cbdc6c9d6
* Impl: 0xBa78AE6A68DB5784e26a7DdCccd3939BB6cd5F57
