#[cfg(test)]
mod lp_unlock_tests {
    use std::ops::Add;
    use std::time::SystemTime;

    use anyhow::Ok;
    use fast_bridge_common::{
        get_eth_address, TransferDataEthereum, TransferDataNear, TransferMessage,
    };
    use near_sdk::borsh::BorshSerialize;
    use near_sdk::json_types::U128;
    use near_sdk::serde_json::json;
    use near_sdk::{ONE_NEAR, ONE_YOCTO};
    use workspaces::operations::Function;
    use workspaces::{network::Sandbox, Account, AccountId, Contract, Worker};

    use crate::StateProof;

    const ETH_BRIDGE_ADDRESS: &str = "DBE11ADC5F9c821341A837f4810123f495fBFd44";
    const ETH_TOKEN_RECIPIENT: &str = "84E1795020A0f3B41F681bf46eb6cf65Ad1362Fc";
    const ETH_TOKEN_ADDRESS: &str = "1c32D17A3a2177FEfA51D2001e543CF001320E71";
    const BRIDGE_WASM_FILEPATH: &str = "../Build_Output/fastbridge_mock.wasm";
    const MOCK_PROVER_WASM_FILEPATH: &str = "../Build_Output/eth_prover_mock.wasm";
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

    async fn deploy_bridge(mut init_input: InitArgs, file_path: &str) -> anyhow::Result<TestData> {
        let worker = workspaces::sandbox().await?;
        println!("$$$$$$$$$$$$$$$$$$$");
        let bridge = worker.dev_deploy(&std::fs::read(file_path)?).await?;
        println!("%%%%%%%%%%%%%%%%%%%%");
        let client = worker
            .dev_deploy(&std::fs::read(MOCK_CLIENT_WASM_FILEPATH)?)
            .await?;
        let prover = worker
            .dev_deploy(&std::fs::read(MOCK_PROVER_WASM_FILEPATH)?)
            .await?;
        let token = worker
            .dev_deploy(&std::fs::read(MOCK_TOKEN_WASM_FILEPATH)?)
            .await?;

        init_input.eth_client_account = Some(
            init_input
                .eth_client_account
                .unwrap_or_else(|| client.id().to_string()),
        );
        init_input.prover_account = Some(
            init_input
                .prover_account
                .unwrap_or_else(|| prover.id().to_string()),
        );
        let result = bridge
            .call("new")
            .args_json(init_input)
            .max_gas()
            .transact()
            .await?;
        assert!(result.is_success());

        let result = token
            .call("new")
            .args_json(json!({
                "owner_id": bridge.id(),
                "total_supply": "0",
                "metadata": {
                    "spec": "ft-1.0.0",
                    "name": "Wrapped usdc",
                    "symbol": "wUSDC",
                    "decimals": 6
                },
            }))
            .max_gas()
            .transact()
            .await?;
        assert!(result.is_success());

        let owner = worker.root_account()?;
        let alice = owner
            .create_subaccount("alice")
            .initial_balance(100 * ONE_NEAR)
            .transact()
            .await?
            .into_result()?;

        let result = token
            .call("storage_deposit")
            .args_json(json!({
                "account_id": bridge.id(),
            }))
            .max_gas()
            .deposit(ONE_NEAR)
            .transact()
            .await?;
        assert!(result.is_success());

        let result = token
            .call("mint")
            .args_json(json!({
                "account_id": alice.id(),
                "amount": "1000000000"
            }))
            .max_gas()
            .transact()
            .await?;
        assert!(result.is_success());

        println!("Mock-eth_client is deployed at: {:?}", client.id());

        let init_mock_eth_client = client.call("init").max_gas().transact().await?;
        if init_mock_eth_client.is_failure() {
            println!(
                "\n\n\n FAILURES while init mock-eth-client: \n\n{:?}\n\n\n",
                init_mock_eth_client.failures()
            );
        } else {
            assert!(init_mock_eth_client.is_success());
        }

        let set_last_block_number_call = client
            .call("set_last_block_number")
            .args_borsh(10 as u64)
            .max_gas()
            .transact()
            .await?;
        if set_last_block_number_call.is_failure() {
            println!(
                "\n\n\n FAILURES while set last block number: \n\n{:?}\n\n\n",
                set_last_block_number_call.failures()
            );
        } else {
            assert!(set_last_block_number_call.is_success());
        }

        // let result = prover
        //     .call("set_log_entry_verification_status")
        //     .args_json(json!({
        //         "verification_status": true,
        //     }))
        //     .max_gas()
        //     .transact()
        //     .await?;
        // assert!(result.is_success());

        Ok(TestData {
            bridge,
            token,
            accounts: [alice].to_vec(),
        })
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

    async fn get_pending_transfer_in_bridge(
        bridge: &Contract,
        token_id: &AccountId,
    ) -> anyhow::Result<U128> {
        let dt = bridge
            .view("get_pending_balance")
            .args_json(json!({
                "token_id": token_id,
            }))
            .await?
            .json()?;
        Ok(dt)
    }

    async fn get_bridge_balance(
        bridge: &Contract,
        account_id: &AccountId,
        token_id: &AccountId,
    ) -> anyhow::Result<U128> {
        Ok(bridge
            .view("get_user_balance")
            .args_json(json!({
                "account_id": account_id,
                "token_id": token_id,
            }))
            .await?
            .json()?)
    }

    async fn transfer_tokens(
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
                amount: (transfer_amount / 2).into(),
            },
            fee: TransferDataNear {
                token: token.id().to_string().parse().unwrap(),
                amount: (fee_amount / 2).into(),
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

    #[tokio::test]
    async fn test_lp_unlock_with_state_proof() -> anyhow::Result<()> {
        let test_data = deploy_bridge(
            InitArgs {
                eth_bridge_contract: ETH_BRIDGE_ADDRESS.to_owned(),
                prover_account: None,
                eth_client_account: None,
                lock_time_min: "1ms".to_owned(),
                lock_time_max: "10h".to_owned(),
                eth_block_time: 0,
                whitelist_mode: false,
            },
            BRIDGE_WASM_FILEPATH,
        )
        .await?;

        let alice = &test_data.accounts[0];
        let alice_initial_token_balance = get_token_balance(&test_data.token, alice.id()).await?.0;
        let bridge_balance = get_token_balance(&test_data.token, test_data.bridge.id())
            .await?
            .0;
        println!(
            "ALICE INITIAL TOKEN BALANCE: {}",
            alice_initial_token_balance
        );
        println!("BRIDGE BALANCE: {}", bridge_balance);
        assert_eq!(bridge_balance, 0); // since owner of token is bridge only
        assert_eq!(alice_initial_token_balance, 1000000000);
        let alice_balance_in_bridge_before_transfer =
            get_bridge_balance(&test_data.bridge, alice.id(), test_data.token.id())
                .await
                .unwrap_or(U128(0))
                .0;
        assert_eq!(
            alice_balance_in_bridge_before_transfer, 0,
            "Alice balance in fast-bridge not matched"
        );

        // token amounts
        let transfer_amount: u128 = 100;
        let fee_amount: u128 = 100;

        // init call fast bridge for ft_transfer_call
        transfer_tokens(
            test_data.bridge.as_account(),
            alice,
            test_data.token.as_account(),
            transfer_amount,
            fee_amount,
        )
        .await?;

        let alice_balance_in_bridge_after_transfer =
            get_bridge_balance(&test_data.bridge, alice.id(), test_data.token.id())
                .await
                .expect("unable to fetch alice balance after transfer");
        println!(
            "Alice Balance in bridge after half transfer: {:?}",
            alice_balance_in_bridge_after_transfer
        );

        let pending_balance_of_token_in_bridge =
            get_pending_transfer_in_bridge(&test_data.bridge, test_data.token.id())
                .await
                .expect("unable to get pending balance");
        println!("Pending balance: {:?}", pending_balance_of_token_in_bridge);
        // check balnce after init-transfer to fast-bridge
        let alice_token_balance_after_transfer =
            get_token_balance(&test_data.token, alice.id()).await?.0;
        println!(
            "Alice token balance after transfer: {}",
            alice_token_balance_after_transfer
        );
        // assert_eq!(alice_token_balance_after_transfer, alice_initial_token_balance - (transfer_amount + fee_amount), "Alice token balance not matched after transfer to bridge");

        Ok(())
    }
}
