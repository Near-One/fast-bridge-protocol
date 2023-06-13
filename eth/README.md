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

## EthErc20FastBridge scripts
This section will help users to deploy and interact with the fast-bridge contract.

### Setup
Before using helper scripts to deploy and interact with the contract, you should set up the environment variables.
The full list of environment variables is provided in `.env.example` file.
Usually, you don't need to set up all of them. To figure out what you need, you can take a closer look at `hardhat.config.js` file.

For example, for interacting with the contract on Goerli network it will be enough to set up:
*  `PRIVATE_KEY`. For Goerli network, you can extract it from MetaMask
*  `INFURA_API_KEY`. You will need to create account on https://www.infura.io/ and create the endpoint for goerli network.

For convenience, you can create a file `.env` and set the environment variables there,  just like in a `.env.example` file.

**WARNING:** Be careful not to accidentally commit this file to git.

### Deploy
You can deploy the contracts to the `Goerli` testnet by using the following commands:
```
npm run deploy:test-tokens -- goerli
npm run deploy:bridge -- goerli
```

After running this scripts the proxy and implementation addresses of `EthErc20FastBridge` will be stored in `scripts/deployment/deploymentAddresses.json` file.

### Deploy and verify
To deploy and verify the fast bridge on goerli network use the following command:

```
yarn run deploy:verify:bridge -- goerli
```

For using this command you will also need to set up the following env variable:
* `ETHERSCAN_API_KEY`

By using this command the `scripts/EthErc20FastBridge/deploy_and_verify_bridge.js` script will be executed.

### Upgrade script
To upgrade bridge contract(using hardhat's upgrades plugin) run:
```
yarn run upgrade:bridge -- goerli
```

For using this command you will also need to set up the following env variable:
* `BRIDGE_PROXY_ADDRESS` -- the Ethereum Fast Bridge Proxy address started with `0x`

By using this command the `scripts/EthErc20FastBridge/upgrade_bridge.js` script will be executed.

### Whitelisting
To interact with EthErc20FastBridge whitelisting methods you can write your own JS script and use
functions from `scripts/EthErc20FastBridge/whitelist_tokens.js`.

The example of script to whitelist one token:
```javascript
const { ethers } = require("hardhat");
const { addTokenToWhitelist } = require("./whitelist_tokens");

const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

async function main() {
    const [signer] = await ethers.getSigners(); // signer must have WHITELISTING_TOKENS_ADMIN_ROLE
    await addTokenToWhitelist(WETH, signer);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
```

The command to run this script:
```
npx hardhat run <path_to_script/script.js>
```

`scripts/EthErc20FastBridge/whitelist_tokens.js` functions:
* `bulkWhitelistStatusUpdate` -- bulk update whitelist status of tokens.
* `addTokenToWhitelist` -- whitelist one token.
* `removeTokenFromWhitelist` -- remove one token from whitelist.
* `isTokenInWhitelist` -- check whether a token is whitelisted or not.


### Pause/Unpause transfers
To interact with EthErc20FastBridge pause and unpause methods you can write your own JS script and use
functions from `scripts/EthErc20FastBridge/pause_unpause.js`.

Methods:
* `pauseTransfer` -- to pause all operations in Fast Bridge
* `unpauseTransfer` -- to unpause all the operations in Fast Bridge.

### To interact with above methods use script `fast-bridge-protocol/eth/scripts/EthErc20FastBridge/interact_with_bridge.js`
You can interact with Fast Bridge in goerli by running:
```bash
npm run interact:bridge -- goerli
```

Note: bridge address will be picked from `fast-bridge-protocol/eth/scripts/deployment/deploymentAddresses.json`


### To interact with FastBridge using hardhat task
You can execute any EthErc20FastBridge method by running:
```bash
npx hardhat method --jsonstring <json_string_input>
```

For example:
```
npx hardhat method --jsonstring '{"methodName":"setWhitelistedTokens","arguments":{"arg1":["0xdAC17F958D2ee523a2206206994597C13D831ec7"],"arg2":[true]}}' --network goerli
```

You should set up the following env variable:
* `TASK_RPC_URL`