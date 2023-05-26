#[cfg(test)]
mod lp_unlock_tests {
    use std::ops::Add;
    use std::time::SystemTime;

    use anyhow::Ok;
    use fast_bridge_common::{
        get_eth_address, TransferDataEthereum, TransferDataNear, TransferMessage,
    };
    use near_sdk::borsh::BorshSerialize;
    use near_sdk::json_types::{self, U128};
    use near_sdk::serde_json;
    use near_sdk::serde_json::json;
    use near_sdk::{ONE_NEAR, ONE_YOCTO};
    use serde::Deserialize;
    use workspaces::{network::Sandbox, Account, AccountId, Contract, Worker};

    use crate::StateProof;

    const ETH_BRIDGE_ADDRESS: &str = "DBE11ADC5F9c821341A837f4810123f495fBFd44";
    const ETH_TOKEN_RECIPIENT: &str = "84E1795020A0f3B41F681bf46eb6cf65Ad1362Fc";
    const ETH_TOKEN_ADDRESS: &str = "1c32D17A3a2177FEfA51D2001e543CF001320E71";
    const BRIDGE_WASM_FILEPATH: &str = "../Build_Output/fastbridge_mock.wasm";
    const MOCK_PROVER_WASM_FILEPATH: &str = "../Build_Output/eth_prover_mock0.wasm";
    const MOCK_CLIENT_WASM_FILEPATH: &str = "../Build_Output/mock_eth_client.wasm";
    const MOCK_TOKEN_WASM_FILEPATH: &str = "../Build_Output/mock_token.wasm";

    #[derive(serde::Serialize)]
    struct InitArgs {
        eth_bridge_contract: String,
        prover_account: Option<String>,
        eth_client_account: Option<String>,
        lock_time_min: String,
        lock_time_max: String,
        eth_block_time: near_sdk::Duration,
        whitelist_mode: bool,
    }
    #[derive(Debug)]
    struct TestData {
        bridge: Contract,
        token: Contract,
        accounts: Vec<Account>,
    }

    async fn create_account(name: &str, worker: Worker<Sandbox>) -> Account {
        let owner = worker.root_account().unwrap();

        let account = owner
            .create_subaccount(name)
            .initial_balance(100 * ONE_NEAR)
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap();

        account
    }

    pub async fn deploy_contract(
        name: &str,
        path_to_wasm: String,
        worker: Worker<Sandbox>,
    ) -> (Account, Contract) {
        let account = create_account(name, worker).await;

        let wasm = std::fs::read(&path_to_wasm).unwrap();
        let contract = account.deploy(&wasm).await.unwrap().unwrap();

        (account, contract)
    }

    pub async fn init_mock_token(token_contract: Contract) -> anyhow::Result<U128> {
        let res = token_contract
            .call("new_default_meta")
            .args_json((token_contract.id(), U128::from(100000000000000000000000000)))
            .max_gas()
            .transact()
            .await?;

        let total_supply = token_contract.call("ft_total_supply").view().await?;
        near_sdk::env::log_str(
            format!(
                "Total Supply in FT contract {}",
                (total_supply.json::<U128>()?).0
            )
            .as_str(),
        );
        let ans = total_supply.json::<U128>()?;
        assert!(res.is_success());
        Ok(ans)
    }

    pub async fn init_eth_client(client_contract: Contract) -> anyhow::Result<()> {
        let call = client_contract.call("init").max_gas().transact().await?;

        assert!(call.is_success(), "eth-client init call failed");
        Ok(())
    }

    pub async fn init_prover(
        prover_contract: Contract,
        eth_client_account_id: AccountId,
    ) -> anyhow::Result<()> {
        let call = prover_contract
            .call("init")
            .args_borsh(eth_client_account_id)
            .max_gas()
            .transact()
            .await?;

        assert!(call.is_success());
        Ok(())
    }

    pub async fn init_near_fastbridge(
        near_bridge_contract: Contract,
        eth_bridge_add: String,
        prover_account: AccountId,
        eth_client_account: AccountId,
        eth_block_time: u64,
    ) -> anyhow::Result<()> {
        let bridge_init_call = near_bridge_contract
            .call("new")
            .args_json(json!(
                {
                    "eth_bridge_contract": eth_bridge_add,
                    "prover_account": prover_account,
                    "eth_client_account": eth_client_account,
                    "lock_time_min": "1ms".to_string(),
                    "lock_time_max": "12hr".to_string(),
                    "eth_block_time": eth_block_time,
                    "whitelist_mode": false
                }
            ))
            .max_gas()
            .transact()
            .await?;

        if bridge_init_call.is_failure() {
            near_sdk::env::log_str(
                format!(
                    "Failure details of init near fast-bridge: {:#?}",
                    bridge_init_call.failures()
                )
                .as_str(),
            );
        } else {
            assert!(bridge_init_call.is_success());
        }
        Ok(())
    }

    pub async fn register_in_ft(
        token_contract: Contract,
        bridge_account: AccountId,
        user_account: AccountId,
    ) -> anyhow::Result<()> {
        let storage_deposit_for_bridge_call_result = token_contract
            .call("storage_deposit")
            .args_json((bridge_account, Option::<bool>::None))
            .deposit(near_sdk::env::storage_byte_cost() * 125)
            .max_gas()
            .transact()
            .await?;

        let storage_deposit_for_user_call_result = token_contract
            .call("storage_deposit")
            .args_json((user_account, Option::<bool>::None))
            .deposit(near_sdk::env::storage_byte_cost() * 125)
            .max_gas()
            .transact()
            .await?;
        if storage_deposit_for_bridge_call_result.is_failure()
            || storage_deposit_for_user_call_result.is_failure()
        {
            near_sdk::env::log_str(
                format!(
                    "Failure details of storage deposit for bridge: {:#?}",
                    storage_deposit_for_bridge_call_result.failures()
                )
                .as_str(),
            );
            near_sdk::env::log_str(
                format!(
                    "Failure details of storage deposit for user: {:#?}",
                    storage_deposit_for_user_call_result.failures()
                )
                .as_str(),
            );
        } else {
            assert!(storage_deposit_for_bridge_call_result.is_success());
            assert!(storage_deposit_for_user_call_result.is_success());
        }

        Ok(())
    }

    pub async fn transfer_ft(
        ft_contract: Contract,
        from: Account,
        recipient_account: Account,
        transfer_amount: U128,
        method_name: &str,
        args: serde_json::Value,
    ) -> anyhow::Result<()> {
        let recipient_balance_before_transfer_call_result = recipient_account
            .call(ft_contract.id(), "ft_balance_of")
            .args_json((recipient_account.id(),))
            .view()
            .await?;

        let recipient_balance_before_transfer =
            (recipient_balance_before_transfer_call_result.json::<U128>()?).0;

        let ft_transfer_to_recipient_call_result = from
            .call(ft_contract.id(), method_name)
            .args_json(&args)
            .deposit(ONE_YOCTO)
            .max_gas()
            .transact()
            .await?;

        if ft_transfer_to_recipient_call_result.is_failure() {
            near_sdk::env::log_str(
                format!(
                    "Failure details of ft-transfer from ft-account to user: {:#?}",
                    ft_transfer_to_recipient_call_result.failures()
                )
                .as_str(),
            );
        } else {
            assert!(ft_transfer_to_recipient_call_result.is_success());
        }

        let recipient_balance_after_transfer_call = recipient_account
            .call(ft_contract.id(), "ft_balance_of")
            .args_json((recipient_account.id(),))
            .view()
            .await?;

        let recipient_balance_after_transfer =
            (recipient_balance_after_transfer_call.json::<U128>()?).0;

        near_sdk::env::log_str(
            format!(
                "Balance of {} after {} from {} is: {}",
                recipient_account.id(),
                method_name,
                from.id(),
                recipient_balance_after_transfer
            )
            .as_str(),
        );

        assert_eq!(
            recipient_balance_after_transfer,
            recipient_balance_before_transfer + transfer_amount.0,
            "Transfered balance of user after transfer not matched"
        );
        Ok(())
    }

    pub async fn get_balance_in_fastbridge(
        bridge_contract: Contract,
        caller_account: Account,
        ft_account: Account,
    ) -> anyhow::Result<u128> {
        let balance_in_bridge_call_result = bridge_contract
            .view("get_user_balance")
            .args_json((caller_account.id(), ft_account.id()))
            .await?;
        let balance_in_bridge = balance_in_bridge_call_result.json::<U128>()?;
        Ok(balance_in_bridge.0)
    }

    pub async fn set_last_block_number(
        eth_client_contract: Contract,
        block_number: u64,
    ) -> anyhow::Result<()> {
        let call = eth_client_contract
            .call("set_last_block_number")
            .args_borsh(block_number)
            .max_gas()
            .transact()
            .await?;

        assert!(call.is_success());

        let block_no = eth_client_contract.call("last_block_number").view().await?;
        let actual_block_from_call = block_no.borsh::<u64>()?;
        assert_eq!(block_number, actual_block_from_call, "block not matched");
        Ok(())
    }

    // Encode the TransferMessage to Base64 vec
    pub fn encode_transfer_msg(msg: TransferMessage) -> near_sdk::json_types::Base64VecU8 {
        let encoded_transfer_message =
            near_sdk::json_types::Base64VecU8::from(msg.try_to_vec().unwrap());
        encoded_transfer_message
    }

    //call init transfer in fast-bridge contract
    async fn init_transfer(
        bridge: &Account,
        user_account: &Account,
        token: &Account,
        transfer_amount: u128,
        fee_amount: u128,
    ) -> anyhow::Result<()> {
        let valid_till = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .add(std::time::Duration::from_secs(180))
            .as_nanos()
            .try_into()
            .expect("Can't convert Duration to u64");

        let eth_token_add = get_eth_address(ETH_TOKEN_ADDRESS.to_string());
        let eth_recipient = get_eth_address(ETH_TOKEN_RECIPIENT.to_string());
        let msg: TransferMessage = TransferMessage {
            valid_till,
            transfer: TransferDataEthereum {
                token_near: token.id().to_string().parse().unwrap(),
                token_eth: eth_token_add,
                amount: (transfer_amount).into(),
            },
            fee: TransferDataNear {
                token: token.id().to_string().parse().unwrap(),
                amount: (fee_amount).into(),
            },
            recipient: eth_recipient,
            valid_till_block_height: None,
        };
        let msg = encode_transfer_msg(msg);

        let init_transfer_call = user_account
            .call(bridge.id(), "init_transfer")
            .args_json(json!({
                "msg": msg,
            }))
            .max_gas()
            .transact()
            .await?;
        if init_transfer_call.is_failure() {
            println!(
                "\n\nINIT TRANSFER CALL FAILURE REASON: \n\n{:?}\n\n",
                init_transfer_call.failures()
            );
        } else {
            assert!(init_transfer_call.is_success(), "init_transfer_call failed");
            println!(
                "init_transfer_call to fastbridge result: {:?}",
                init_transfer_call.clone().json::<U128>()?.0
            );
        }

        Ok(())
    }

    async fn get_token_balance(token: &Contract, account_id: &AccountId) -> anyhow::Result<U128> {
        Ok(token
            .view("ft_balance_of")
            .args_json(json!({
                "account_id": account_id,
            }))
            .await?
            .json()?)
    }

    async fn transfer_tokens_with_msg(
        bridge: &Account,
        account: &Account,
        token: &Account,
        transfer_amount: u128,
        fee_amount: u128,
    ) -> anyhow::Result<()> {
        let valid_till = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .add(std::time::Duration::from_secs(180))
            .as_nanos()
            .try_into()
            .expect("Can't convert Duration to u64");

        let eth_token_add = get_eth_address(ETH_TOKEN_ADDRESS.to_string());
        let eth_recipient = get_eth_address(ETH_TOKEN_RECIPIENT.to_string());
        let msg: TransferMessage = TransferMessage {
            valid_till,
            transfer: TransferDataEthereum {
                token_near: token.id().to_string().parse().unwrap(),
                token_eth: eth_token_add,
                amount: (transfer_amount).into(),
            },
            fee: TransferDataNear {
                token: token.id().to_string().parse().unwrap(),
                amount: (fee_amount).into(),
            },
            recipient: eth_recipient,
            valid_till_block_height: None,
        };
        let msg = near_sdk::base64::encode(msg.try_to_vec().unwrap());

        let result = account
            .call(token.id(), "ft_transfer_call")
            .args_json(json!({
                "receiver_id": bridge.id(),
                "amount": (transfer_amount + fee_amount).to_string(),
                "msg": msg,
            }))
            .max_gas()
            .deposit(ONE_YOCTO)
            .transact()
            .await?;
        assert!(result.is_success(), "ft_transfer_call failed");
        println!(
            "ft_transfer_call to fastbridge result: {:?}",
            result.clone().json::<U128>()?.0
        );
        assert_eq!(
            result.clone().json::<U128>()?.0,
            0,
            "ft_transfer_call result not matched"
        );
        Ok(())
    }

    #[derive(Debug, Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    pub struct JsonProof {
        #[serde(with = "hex::serde")]
        pub header_data: Vec<u8>,
        pub account_proof: Vec<String>, // account proof
        #[serde(with = "hex::serde")]
        pub account_data: Vec<u8>, // encoded account state
        pub storage_proof: Vec<String>, // storage proof
    }
    fn get_proof_from_json(file_path: String) -> JsonProof {
        let contents = std::fs::read_to_string(&file_path).expect("Unable to read file");
        serde_json::from_str(&contents).expect("Unable to deserialize")
    }

    fn get_lp_unlock_proof(file_path: String) -> StateProof {
        let json_proof = get_proof_from_json(file_path);
        let header_data = json_proof.header_data;
        let account_proof = json_proof
            .account_proof
            .into_iter()
            .map(|x| hex::decode(x).unwrap())
            .collect();
        let account_data = json_proof.account_data;
        let storage_proof = json_proof
            .storage_proof
            .into_iter()
            .map(|x| hex::decode(x).unwrap())
            .collect();

        StateProof {
            header_data,
            account_proof,
            account_data,
            storage_proof,
        }
    }

    /*
    Currently lp_unlock_proof.json is for below transfer data
    {
        token: "0x1c32D17A3a2177FEfA51D2001e543CF001320E71",
        recipient: "0x84e1795020a0f3b41f681bf46eb6cf65ad1362fc",
        nonce: 3,
        amount: 100
    }
    Included in block (Polygon Mumbai) = 36021022;
    Txn: https://mumbai.polygonscan.com/tx/0x77a4562a1e4d4d615f696244d3b47df0d74a7808dd4c7c07651d0f02ee65816d
     */
    async fn lp_unlock_tokens(
        bridge: &Account,
        relayer_account: &Account,
        nonce: u128,
    ) -> anyhow::Result<()> {
        let lp_unlock_proof =
            get_lp_unlock_proof(String::from("./src/tests/test_data/lp_unlock_proof.json"));
        println!("RELAYER ACCOUNT IS : {}", relayer_account.id());
        // println!("\n\n\n LP UNLOCK PROOF IS: \n\n{:?}\n\n", lp_unlock_proof);
        // let lp_unlock_proof = near_sdk::base64::encode(lp_unlock_proof.try_to_vec().unwrap());
        let lp_unlock_proof =
            near_sdk::json_types::Base64VecU8::from(lp_unlock_proof.try_to_vec().unwrap());

        let lp_unlock_call = relayer_account
            .call(bridge.id(), "lp_unlock")
            .args_json(json!({
                "nonce": json_types::U128::from(nonce),
                "proof": lp_unlock_proof,
                "_unlock_recipient": relayer_account.id(),
            }))
            .max_gas()
            .transact()
            .await?;

        if lp_unlock_call.is_failure() {
            println!(
                "\n\nLP UNLOCK CALLED FAILED WITH REASON\n\n{:?}\n\n",
                lp_unlock_call.failures()
            );
        } else {
            assert!(lp_unlock_call.is_success());
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_lp_unlock_with_state_proof() -> anyhow::Result<()> {
        let worker = workspaces::sandbox().await?;

        // deploy mock nep-141
        let (mock_token_account, mock_token_contract) = deploy_contract(
            "mock_token",
            MOCK_TOKEN_WASM_FILEPATH.to_string(),
            worker.to_owned(),
        )
        .await;

        // init mock token
        init_mock_token(mock_token_contract.to_owned()).await?;

        // deploy mock eth-client
        let (mock_eth_client_account, mock_eth_client_contract) = deploy_contract(
            "eth_client",
            MOCK_CLIENT_WASM_FILEPATH.to_string(),
            worker.to_owned(),
        )
        .await;

        // init eth-client contract
        init_eth_client(mock_eth_client_contract.to_owned()).await?;

        // deploy mock eth-prover
        let (prover_account, prover_contract) = deploy_contract(
            "prover",
            MOCK_PROVER_WASM_FILEPATH.to_string(),
            worker.to_owned(),
        )
        .await;

        //init prover contract
        init_prover(prover_contract, mock_eth_client_account.id().to_owned()).await?;

        // deploy near fast-bridge contract
        let (fast_bridge_account, fast_bridge_contract) = deploy_contract(
            "fastbridge",
            BRIDGE_WASM_FILEPATH.to_string(),
            worker.to_owned(),
        )
        .await;

        // init fast-bridge contract
        init_near_fastbridge(
            fast_bridge_contract.to_owned(),
            ETH_BRIDGE_ADDRESS.to_string(),
            prover_account.id().to_owned(),
            mock_eth_client_account.id().to_owned(),
            12000000000u64,
        )
        .await?;

        //create user 'jordan' for init transfer
        let jordan_account = create_account("jordan", worker.to_owned()).await;

        // Register the user and fast-bridge in mock-token with storage deposit
        register_in_ft(
            mock_token_contract.to_owned(),
            fast_bridge_account.id().to_owned(),
            jordan_account.id().to_owned(),
        )
        .await?;

        // Transfer some FT to user 'jordan' from FT-owner account
        let ft_transfer_amount = U128::from(1000_000_000_000); // 10^12 -> 10^6 USDC
        let ft_transfer_args = json!({
            "receiver_id": jordan_account.id().to_owned().as_str(),
            "amount":ft_transfer_amount,
            "memo":Option::<bool>::None,
        });
        transfer_ft(
            mock_token_contract.to_owned(),
            mock_token_account.to_owned(),
            jordan_account.to_owned(),
            ft_transfer_amount,
            "ft_transfer",
            ft_transfer_args,
        )
        .await?;

        // transfer tokens to fast-bridge from jordan's account for init-transfer
        let transfer_amount = U128::from(1000_000_000); // 10^9 -> 10^3 USDC
        let ft_transfer_call_args = json!({
            "receiver_id": fast_bridge_account.id().to_owned().as_str(),
            "amount": transfer_amount,
            "memo": Option::<bool>::None,
            "msg": "".to_string()
        });
        transfer_ft(
            mock_token_contract.to_owned(),
            jordan_account.to_owned(),
            fast_bridge_account.to_owned(),
            transfer_amount,
            "ft_transfer_call",
            ft_transfer_call_args,
        )
        .await?;

        // check balance of 'jordan' in fast-bridge and FT contract after transfer
        let jordan_balance_in_bridge_after_transfer = get_balance_in_fastbridge(
            fast_bridge_contract.to_owned(),
            jordan_account.to_owned(),
            mock_token_account.to_owned(),
        )
        .await?;
        assert_eq!(
            jordan_balance_in_bridge_after_transfer, 1000000000u128,
            "Balance of jordan in fast-bridge after transfer not matched"
        );
        let jordan_balance_in_ft_after_transfer = get_token_balance(
            &mock_token_contract.to_owned(),
            &jordan_account.id().to_owned(),
        )
        .await?
        .0;
        assert_eq!(
            jordan_balance_in_ft_after_transfer,
            1000_000_000_000 - 1000_000_000,
            "Balance of jordan in FT after transfer to fast-bridge not matched"
        );

        //set last block number in eth-client
        set_last_block_number(mock_eth_client_contract.to_owned(), 10u64).await?;

        // init transfer call to initite the token transfer from Near -> Ethereum
        let transfer_amount = 100u128;
        let fee_amount = 100u128;
        init_transfer(
            &fast_bridge_account.to_owned(),
            &jordan_account.to_owned(),
            &mock_token_account.to_owned(),
            transfer_amount,
            fee_amount,
        )
        .await?;

        //create relayer account as used for _unlock_recipient
        let relayer_account = create_account("relayer", worker.to_owned()).await;

        // call lp_unlock rom relayer account with state proof
        lp_unlock_tokens(
            &fast_bridge_account.to_owned(),
            &relayer_account.to_owned(),
            1u128,
        )
        .await?;

        Ok(())
    }
}
