# fast-bridge-protocol

RB Fast bridge is one-way decentralized trustless bridge created to speed up transfers from Near to Ethereum.

## How it works
1) User initiate unique transfer `{nonce, amount, {fee_token, fee_amount}, recipient, valid_till}` that is valid for some reasonably small period of time. That locks `amount` and `fee_amount` on NearErc20FastBridge contract
2) NearErc20FastBridge contract generates `FastBridgeTransferEvent` with the following metadata `{nonce, valid_till, transfer: {token_near, token_eth, amount}, fee: {token, amount}, recipient}`
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

### Ethereum
Described in the corresponding [README](eth/README.md)

### Near
Described in the corresponding [README](near/README.md)


## EthErc20Bridge scripts
Below given command will help user to deploy and interact with contracts on the network provided as arg to below command, if no arg is provided it will use default network from hardhat-config.

First set up your `.env` file in `spectere-bridge-protocol/.env`, for help `.env.example` is provided in `spectere-bridge-protocol` directory.
1. First copy content of `.env.example` file
2. Create a new file in `spectere-bridge-protocol` directory and name it `.env`
3. Paste copied content in `.env` file 
4. Fill up details as required as per used in `hardhat.config.json` file.

Then, to run below scripts go to `spectere-bridge-protocol/eth` directory, i.e. **run command `cd eth`**

example : to deploy EthErc20FastBridge on <network-name> network (network-name must be defined in hardhat-config.json's networks)
`npm run deploy:bridge -- <network-name>`

### Deployment script
Running ths script will deploy bridge proxy and store proxy and implementation address in `spectre-bridge-protocol/eth/scripts/deployment/deploymentAddresses.json`
To execute this script => run command `yarn run deploy:bridge -- <network-name>`
example : to deploy bridge on goerli run command `yarn run deploy:bridge -- goerli`

### Deploy and verify
Running this script will first deploy and then verify bridge.
To execute this script => run command `yarn run deploy:verify:bridge -- <network-name>`
example : to deploy and verify bridge on goerli run command `yarn run deploy:verify:bridge -- goerli`

### Upgrade script 
To upgrade bridge contract(using hardhat's upgrades plugin), use `spectre-bridge-protocol/eth/scripts/EthErc20FastBridge/upgrade_bridge.js` script.
<!-- Before upgrading, go to file `spectre-bridge-protocol/eth/scripts/EthErc20FastBridge/upgrade_bridge.js` and update current bridge proxy address at line 7. -->

To execute this script => run command `yarn run upgrade:bridge -- <network-name>`
example : to upgrade on goerli run command `yarn run deploy:verify:bridge -- goerli`

### Whitelisting
To interact with EthErc20FastBridge whitelisting methods use methods defined in spectre-bridge-protocol/eth/scripts/EthErc20FastBridge/whitelistTokens.js

* To bulk update whitelist status of tokens import and use method `bulkWhitelistStatusUpdate` from above mentioned file with an array of token addresses, an array of their corresponding status and a signer with `WHITELISTING_TOKENS_ADMIN_ROLE` as parameters.

* To whitelist one token import and use method `addTokenToWhitelist` from above mentioned file with a token address and a signer with `WHITELISTING_TOKENS_ADMIN_ROLE` as parameters.

* To remove one token from whitelist use method `removeTokenFromWhitelist` from above mentioned file with tokens address and signer with `WHITELISTING_TOKENS_ADMIN_ROLE` as parameters.

* To check whether a token is whitelisted or not import and use method `isTokenInWhitelist` from above mentioned file with tokens address and signer with `WHITELISTING_TOKENS_ADMIN_ROLE` as parameters.  

example : If you want whitelist whitelist one token, script would like,
```
const { ethers } = require("hardhat");
const { addTokenToWhitelist } = require("./whitelistTokens");

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
And to run above script run `npx hardhat run <path_to_script/script.js> --` from eth folder.

### Pause/Unpause transfers
To interact with EthErc20FastBridge pause and unpause methods use methods defined in spectre-bridge-protocol/eth/scripts/EthErc20FastBridge/pause_unPause.js

* To pause transfers import and use `pauseTransfer` method from above mentioned file with a signer with `PAUSABLE_ADMIN_ROLE` as parameter. 

* To unpause transfers import and use `unpauseTransfer` method from above mentioned file with a signer with `UNPAUSABLE_ADMIN_ROLE` as parameter. 

These methods can be used in similar to above example

### To interact with above methods use script `spectre-bridge-protocol/eth/scripts/EthErc20FastBridge/interact_with_bridge.js`
Follow below steps to execute script and start interacting
1. First, create your `.env` file(mentioned in `EthErc20Bridge scripts` section's starting)
2. Go to `spectre-bridge-protocol/eth` directory in terminal
3. Run command `npm run interact:bridge -- <network_name_as_defined_in_hardhat_config>` 
4. Follow guide in terminal
Note: bridge address will be picked from `deploymentAddress[network].new.bridge` (from `spectre-bridge-protocol/eth/scripts/deployment/deploymentAddresses.json`)

### To interact with FastBridge using hardhat task
1. To call any method of EthErc20FastBridge use hardhat task `method` 
    Run command `npx hardhat method --jsonstring <json_string_input>`
    
    to create `json_string_input`
    1. create json with `signature` and `arguments` properties in below example format
    ```
    {
        "signature": "setWhitelistedTokens(address[],bool[])",
        "argcount": "2",
        "arguments": {
            "arg1": [
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                "0xB8c77482e45F1F44dE1745F52C74426C631bDD52",
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            ],
            "arg2": [
                true,
                true,
                true
            ]
        }
    }
    ```
    2. pass below json to JSON.stringify() and use output as `json_string_input`

    
    For example: to call `setWhitelistedTokens` method run command 
    ```
    npx hardhat method --jsonstring '{"signature":"setWhitelistedTokens","arguments":{"arg1":["0xdAC17F958D2ee523a2206206994597C13D831ec7"],"arg2":[true]}}'
    ```

2. To deploy fast-bridge run `npx hardhat deploy_fastbridge --verification <bool> --network <network_name>` , here `--verification` is an optional parameter with default value `false` if passed `true` than contract is verified just after the deployment.
3. To verify already deployed contract on same network run `npx hardhat verify_bridge --proxyaddress <fastbridge_proxy_address> --network <network_name>`
4. To whitelists single erc20 token in fast-bridge run `npx hardhat whitelists_token --tokenaddress <token_address> --network <network_name>`, here the pvt key of signer need to have the authorised role to make successful txn and key is picked from .env file so you need to setup it before running the cmd.
   <br>For example:
   ```
   npx hardhat whitelists_token --tokenaddress 0xb2d75C5a142A68BDA438e6a318C7FBB2242f9693 --network mumbai  
   ```
5.  To whitelists token in bulk run `npx hardhat whitelists_token_in_bulk --tokenaddresses <comma_separated_token_addresses> --whiteliststatus <comma_separated_bool_value> --network <network_name>`
   <br>For example:-
    ```
    npx hardhat whitelists_token_in_bulk --tokenaddresses 0xF0b0c5E2c3A35213992bD9b45Af352D6D4035203,0xaa2D6608241B6B930BCcaFE245eFDf052e46C9aA --whiteliststatus true,true,true --network mumbai
    ``` 
    Here also signer need to have the access role to make txn successful.
6. To check whether the token is whitelisted or not run `npx hardhat is_token_whitelisted --tokenaddress <token_address> --network <network_name>`
7. To remove token from whitelists run `npx hardhat remove_token_from_whitelists --tokenaddress <token_address> --network <network_name>` 
    <br>For example:
    ```
    npx hardhat remove_token_from_whitelists --tokenaddress 0xb2d75C5a142A68BDA438e6a318C7FBB2242f9693 --network mumbai
    ```
8. To pause fast_bridge run `npx hardhat pause_fastbridge --network <network_name>`, here the signer needs to have desired role to do so.
9. To unpause fast_bridge run `npx hardhat unpause_fastbridge --network <network_name>`, here also the signer needs to have proper access role to do so.
10. To upgrade the fastbridge run `npx hardhat upgrade_fastbridge --network <network_name>`, here the signer needs to have the proper admin role to upgrade the fast-bridge contract.