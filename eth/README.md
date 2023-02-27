# fast-bridge-solidity

### Build & Test
To build and test contracts run following snippet
```
npm i
npm run test:mainnet-fork
```

To generate the flatten contracts and storage layout 
```
npm run flatten
npm run storage-layout
```

### Deploy
Deployment is configured only for `Goerli` testnet and could be done with the following scirpt
```
npm run deploy:test-tokens
npm run deploy:bridge
```
