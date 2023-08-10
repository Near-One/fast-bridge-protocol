#[cfg(test)]
mod tests {
    use aurora_sdk_integration_tests::aurora_engine::erc20::ERC20;
    use aurora_sdk_integration_tests::aurora_engine_types::parameters::engine::{
        SubmitResult, TransactionStatus,
    };
    use aurora_sdk_integration_tests::aurora_engine_types::H160;
    use aurora_sdk_integration_tests::workspaces::result::ExecutionFinalResult;
    use aurora_sdk_integration_tests::workspaces::{Account, Contract, Worker};
    use aurora_sdk_integration_tests::{
        aurora_engine::{self, AuroraEngine},
        aurora_engine_types::{
            parameters::engine::{CallArgs, FunctionCallArgsV1},
            types::{Address, Wei},
            U256,
        },
        ethabi, tokio,
        utils::{ethabi::DeployedContract, forge, process},
        wnear,
        workspaces::{self, AccountId},
    };
    use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
    use std::path::Path;
    use std::thread::sleep;
    use std::time::Duration;
    use aurora_sdk_integration_tests::wnear::Wnear;
    use aurora_sdk_integration_tests::workspaces::network::Sandbox;
    use fast_bridge_common;
    use fast_bridge_common::EthAddress;

    const ATTACHED_NEAR: u128 = 5_000_000_000_000_000_000_000_000;
    const NEAR_DEPOSIT: u128 = 2_000_000_000_000_000_000_000_000;

    const TRANSFER_TOKENS_AMOUNT: u64 = 100;
    const TOKEN_SUPPLY: u64 = 1000000000;

    #[derive(Default, BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq)]
    pub struct UnlockProof {
        header_data: Vec<u8>,
        account_proof: Vec<Vec<u8>>,
        account_data: Vec<u8>,
        storage_proof: Vec<Vec<u8>>,
    }

    struct TestsInfrastructure {
        worker: Worker<Sandbox>,
        engine: AuroraEngine,
        wnear: Wnear,
        user_account: Account,
        user_address: Address,
        aurora_fast_bridge_contract: DeployedContract,
        mock_token: Contract,
        mock_eth_client: Contract,
        mock_eth_prover: Contract,
        near_fast_bridge: Contract,
        aurora_mock_token: ERC20,
    }

    impl TestsInfrastructure {
        pub async fn init() -> Self {
            let worker = workspaces::sandbox().await.unwrap();
            let engine = aurora_engine::deploy_latest(&worker)
                .await
                .unwrap();

            let wnear = wnear::Wnear::deploy(&worker, &engine).await.unwrap();
            let user_account = worker.dev_create_account().await.unwrap();
            println!("user_account: {:?}", user_account);
            let user_address = aurora_sdk_integration_tests::aurora_engine_sdk::types::near_account_to_evm_address(
                user_account.id().as_bytes(),
            );
            let mock_token = deploy_mock_token(&worker, user_account.id()).await;
            println!("mock token: {:?}", mock_token);

            let mock_eth_client = deploy_mock_eth_client(&worker).await;
            let mock_eth_prover = deploy_mock_eth_prover(&worker).await;

            let near_fast_bridge = deploy_near_fast_bridge(&worker, user_account.id(), &mock_token.id().to_string(), &mock_eth_client.id().to_string(), &mock_eth_prover.id().to_string()).await;
            println!("near fast bridge: {:?}", near_fast_bridge);

            let aurora_fast_bridge_contract = deploy_aurora_fast_bridge_contract(
                &engine,
                &user_account,
                wnear.aurora_token.address,
                &near_fast_bridge
            )
                .await;

            let aurora_mock_token = engine.bridge_nep141(mock_token.id()).await.unwrap();

            TestsInfrastructure {
                worker,
                engine,
                wnear,
                user_account,
                user_address,
                aurora_fast_bridge_contract,
                mock_token,
                mock_eth_client,
                mock_eth_prover,
                near_fast_bridge,
                aurora_mock_token,
            }
        }

        pub async fn mint_wnear(&self, user_address: Option<Address>) {
            self.engine
                .mint_wnear(
                    &self.wnear,
                    user_address.unwrap_or(self.user_address),
                    2 * (ATTACHED_NEAR + NEAR_DEPOSIT),
                )
                .await
                .unwrap();
        }

        pub async fn approve_spend_wnear(&self, user_account: Option<Account>) {
            approve_spend_tokens(
                &self.wnear.aurora_token,
                self.aurora_fast_bridge_contract.address,
                &user_account.unwrap_or(self.user_account.clone()),
                &self.engine,
            ).await;
        }

        pub async fn register_token(&self, user_account: Option<Account>, check_result: bool) {
            aurora_fast_bridge_register_token(
                &self.aurora_fast_bridge_contract,
                self.aurora_mock_token.address.raw(),
                self.mock_token.id().to_string(),
                &user_account.unwrap_or(self.user_account.clone()),
                &self.engine,
                check_result
            ).await;
        }

        pub async fn approve_spend_mock_tokens(&self) {
            approve_spend_tokens(
                &self.aurora_mock_token,
                self.aurora_fast_bridge_contract.address,
                &self.user_account,
                &self.engine,
            ).await;
        }

        pub async fn init_token_transfer(&self) {
            let valid_till = (std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                + Duration::from_secs(30).as_nanos()) as u64;

            let transfer_msg = fast_bridge_common::TransferMessage{
                valid_till,
                transfer: fast_bridge_common::TransferDataEthereum {
                    token_near: self.mock_token.id().parse().unwrap(),
                    token_eth: EthAddress(self.aurora_mock_token.address.raw().0),
                    amount: near_sdk::json_types::U128::from(100)
                },
                fee: fast_bridge_common::TransferDataNear {
                    token: self.mock_token.id().parse().unwrap(),
                    amount: near_sdk::json_types::U128::from(0)
                },
                recipient: EthAddress(self.user_address.raw().0),
                valid_till_block_height: None,
                aurora_sender: Some(EthAddress(self.user_address.raw().0))
            };

            let mut transfer_msg_borsh_hex = serde_json::to_string(&hex::encode(transfer_msg.try_to_vec().unwrap().as_slice())).unwrap();
            transfer_msg_borsh_hex.pop();
            transfer_msg_borsh_hex.remove(0);

            let contract_args = self.aurora_fast_bridge_contract.create_call_method_bytes_with_args(
                "initTokenTransfer",
                &[
                    ethabi::Token::Bytes(transfer_msg.try_to_vec().unwrap())
                ],
            );

            let res = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true
            )
                .await
                .unwrap();
        }

        pub async fn withdraw(&self) {
            let contract_args = self.aurora_fast_bridge_contract.create_call_method_bytes_with_args(
                "withdraw",
                &[
                    ethabi::Token::String(self.mock_token.id().to_string()),
                ],
            );

            call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true
            )
                .await
                .unwrap();
        }

        pub async fn get_mock_token_balance(&self) -> U256 {
            self.engine
                .erc20_balance_of(&self.aurora_mock_token, self.user_address)
                .await
                .unwrap()
        }

        pub async fn increment_current_eth_block(&self) {
            self.mock_eth_client.call("set_last_block_number")
                .args_json(serde_json::json!({
                "block_number": 100
            }))
                .transact()
                .await
                .unwrap()
                .into_result()
                .unwrap();
        }

        pub async fn unlock(&self) {
            let unlock_proof = UnlockProof{
                header_data: vec![],
                account_proof: vec![],
                account_data: vec![],
                storage_proof: vec![]
            };

            let unlock_proof_str = near_sdk::base64::encode(unlock_proof.try_to_vec().unwrap());

            let contract_args = self.aurora_fast_bridge_contract.create_call_method_bytes_with_args(
                "unlock",
                &[
                    ethabi::Token::Uint(U256::one()),
                    ethabi::Token::String(unlock_proof_str)
                ],
            );

            call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true
            )
                .await
                .unwrap();
        }

        pub async fn withdraw_from_near(&self) {
            let contract_args = self.aurora_fast_bridge_contract.create_call_method_bytes_with_args(
                "withdrawFromNear",
                &[
                    ethabi::Token::String(self.mock_token.id().to_string()),
                    ethabi::Token::Uint(U256::from(100))
                ],
            );

            call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true
            )
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn test_init_token_transfer() {
        let infra = TestsInfrastructure::init().await;

        mint_tokens_near(&infra.mock_token, infra.engine.inner.id()).await;

        infra.mint_wnear(None).await;
        infra.approve_spend_wnear(None).await;

        infra.register_token(None, true).await;

        storage_deposit(&infra.mock_token, infra.engine.inner.id(), None).await;
        storage_deposit(&infra.mock_token, infra.near_fast_bridge.id(), None).await;
        engine_mint_tokens(infra.user_address, &infra.aurora_mock_token, &infra.engine).await;

        infra.approve_spend_mock_tokens().await;

        let balance0 = infra.get_mock_token_balance().await;
        infra.init_token_transfer().await;

        let balance1 = infra.get_mock_token_balance().await;
        assert_eq!(balance1 + TRANSFER_TOKENS_AMOUNT, balance0);

        infra.withdraw().await;
        let balance2 = infra.get_mock_token_balance().await;
        assert_eq!(balance2, balance1);

        infra.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));
        infra.unlock().await;
        infra.withdraw_from_near().await;
        infra.withdraw().await;

        let balance3 = infra.get_mock_token_balance().await;
        assert_eq!(balance3, balance0);
    }

    async fn storage_deposit(token_contract: &Contract, account_id: &str, deposit: Option<u128>) {
        let outcome = token_contract
            .call("storage_deposit")
            .args_json(serde_json::json!({ "account_id": account_id }))
            .max_gas()
            .deposit(deposit.unwrap_or(1_250_000_000_000_000_000_000))
            .transact()
            .await
            .unwrap();

        assert!(
            outcome.failures().is_empty(),
            "Call to set failed: {:?}",
            outcome.failures()
        );
    }

    async fn aurora_fast_bridge_register_token(
        aurora_fast_bridge: &DeployedContract,
        engine_mock_token_address: H160,
        near_mock_token_account_id: String,
        user_account: &Account,
        engine: &AuroraEngine,
        check_result: bool
    ) {
        let contract_args = aurora_fast_bridge.create_call_method_bytes_with_args(
            "registerToken",
            &[
                ethabi::Token::Address(engine_mock_token_address),
                ethabi::Token::String(near_mock_token_account_id),
            ],
        );

        call_aurora_contract(
            aurora_fast_bridge.address,
            contract_args,
            user_account,
            engine.inner.id(),
            check_result
        )
            .await
            .unwrap();
    }

    async fn approve_spend_tokens(
        token_contract: &ERC20,
        spender_address: Address,
        user_account: &Account,
        engine: &AuroraEngine,
    ) {
        let evm_input = token_contract.create_approve_call_bytes(spender_address, U256::MAX);
        let result = engine
            .call_evm_contract_with(user_account, token_contract.address, evm_input, Wei::zero())
            .await
            .unwrap();
        aurora_engine::unwrap_success(result.status).unwrap();
    }

    async fn deploy_aurora_fast_bridge_contract(
        engine: &AuroraEngine,
        user_account: &workspaces::Account,
        wnear_address: Address,
        near_fast_bridge: &Contract
    ) -> DeployedContract {
        let contract_path = "../contracts";

        let aurora_sdk_path = Path::new("./aurora-contracts-sdk/aurora-solidity-sdk");
        let codec_lib = forge::deploy_codec_lib(&aurora_sdk_path, engine)
            .await
            .unwrap();
        let utils_lib = forge::deploy_utils_lib(&aurora_sdk_path, engine)
            .await
            .unwrap();
        let aurora_sdk_lib =
            forge::deploy_aurora_sdk_lib(&aurora_sdk_path, engine, codec_lib, utils_lib)
                .await
                .unwrap();

        let constructor = forge::forge_build(
            contract_path,
            &[
                format!(
                    "@auroraisnear/aurora-sdk/aurora-sdk/AuroraSdk.sol:AuroraSdk:0x{}",
                    aurora_sdk_lib.encode()
                ),
                format!(
                    "@auroraisnear/aurora-sdk/aurora-sdk/Utils.sol:Utils:0x{}",
                    utils_lib.encode()
                ),
            ],
            &["out", "AuroraErc20FastBridge.sol", "AuroraErc20FastBridge.json"],
        )
        .await
        .unwrap();

        let deploy_bytes = constructor.create_deploy_bytes_without_constructor();

        let address = engine
            .deploy_evm_contract_with(user_account, deploy_bytes)
            .await
            .unwrap();

        let aurora_fast_bridge_impl = constructor.deployed_at(address);

        let contract_args = aurora_fast_bridge_impl.create_call_method_bytes_with_args(
            "initialize",
            &[
                ethabi::Token::Address(wnear_address.raw()),
                ethabi::Token::String(near_fast_bridge.id().to_string()),
                ethabi::Token::String(engine.inner.id().to_string()),
                ethabi::Token::Bool(false)
            ],
        );

        call_aurora_contract(
            aurora_fast_bridge_impl.address,
            contract_args,
            &user_account,
            engine.inner.id(),
            true
        ).await.unwrap();

        return aurora_fast_bridge_impl;
    }

    async fn deploy_mock_token(
        worker: &workspaces::Worker<workspaces::network::Sandbox>,
        user_account_id: &str
    ) -> workspaces::Contract {
        let contract_path = Path::new("../../near/contracts/");
        let output = tokio::process::Command::new("cargo")
            .current_dir(contract_path)
            .env("RUSTFLAGS", "-C link-arg=-s")
            .args([
                "build",
                "--all",
                "--target",
                "wasm32-unknown-unknown",
                "--release",
            ])
            .output()
            .await
            .unwrap();
        process::require_success(&output).unwrap();
        let artifact_path =
            contract_path.join("target/wasm32-unknown-unknown/release/mock_token.wasm");
        let wasm_bytes = tokio::fs::read(artifact_path).await.unwrap();
        let mock_token = worker.dev_deploy(&wasm_bytes).await.unwrap();

        mock_token
            .call("new_default_meta")
            .args_json(serde_json::json!({"owner_id": user_account_id, "name": "MockToken", "symbol": "MCT", "total_supply": format!("{}", TOKEN_SUPPLY)}))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap();

        mock_token
    }

    async fn deploy_mock_eth_client(
        worker: &workspaces::Worker<workspaces::network::Sandbox>,
    ) -> workspaces::Contract {
        let contract_path = Path::new("../../near/contracts/");
        let output = tokio::process::Command::new("cargo")
            .current_dir(contract_path)
            .env("RUSTFLAGS", "-C link-arg=-s")
            .args([
                "build",
                "--all",
                "--target",
                "wasm32-unknown-unknown",
                "--release",
            ])
            .output()
            .await
            .unwrap();
        process::require_success(&output).unwrap();
        let artifact_path =
            contract_path.join("target/wasm32-unknown-unknown/release/mock_eth_client.wasm");
        let wasm_bytes = tokio::fs::read(artifact_path).await.unwrap();
        let mock_eth_client = worker.dev_deploy(&wasm_bytes).await.unwrap();

        mock_eth_client
    }

    async fn deploy_mock_eth_prover(
        worker: &workspaces::Worker<workspaces::network::Sandbox>,
    ) -> workspaces::Contract {
        let contract_path = Path::new("../../near/contracts/");
        let output = tokio::process::Command::new("cargo")
            .current_dir(contract_path)
            .env("RUSTFLAGS", "-C link-arg=-s")
            .args([
                "build",
                "--all",
                "--target",
                "wasm32-unknown-unknown",
                "--release",
            ])
            .output()
            .await
            .unwrap();
        process::require_success(&output).unwrap();
        let artifact_path =
            contract_path.join("target/wasm32-unknown-unknown/release/mock_eth_prover.wasm");
        let wasm_bytes = tokio::fs::read(artifact_path).await.unwrap();
        let mock_eth_prover = worker.dev_deploy(&wasm_bytes).await.unwrap();

        mock_eth_prover
            .call("set_log_entry_verification_status")
            .args_json(serde_json::json!({
                "verification_status": true
            })).max_gas().transact().await.unwrap().into_result().unwrap();

        mock_eth_prover
    }

    async fn deploy_near_fast_bridge(
        worker: &workspaces::Worker<workspaces::network::Sandbox>,
        user_account_id: &str,
        mock_token_account_id: &str,
        mock_eth_client: &str,
        mock_eth_prover: &str
    ) -> workspaces::Contract {
        let contract_path = Path::new("../../near/contracts/");
        let output = tokio::process::Command::new("cargo")
            .current_dir(contract_path)
            .env("RUSTFLAGS", "-C link-arg=-s")
            .args([
                "build",
                "--all",
                "--target",
                "wasm32-unknown-unknown",
                "--release",
            ])
            .output()
            .await
            .unwrap();

        process::require_success(&output).unwrap();
        let artifact_path =
            contract_path.join("target/wasm32-unknown-unknown/release/fastbridge.wasm");
        let wasm_bytes = tokio::fs::read(artifact_path).await.unwrap();
        let fast_bridge = worker.dev_deploy(&wasm_bytes).await.unwrap();

        fast_bridge
            .call("new")
            .args_json(serde_json::json!({
                "eth_bridge_contract": "DBE11ADC5F9c821341A837f4810123f495fBFd44",
                "prover_account": mock_eth_prover,
                "eth_client_account": mock_eth_client,
                "lock_time_min": "1s",
                "lock_time_max": "24h",
                "eth_block_time": 12000000000u128,
                "whitelist_mode": true,
                "start_nonce": "0",
            }))
            .max_gas()
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap();

        fast_bridge
            .call("acl_grant_role")
            .args_json(serde_json::json!({
                "account_id": fast_bridge.id().to_string(),
                "role": "WhitelistManager"
            })).max_gas().transact().await.unwrap().into_result().unwrap();

        fast_bridge
            .call("set_token_whitelist_mode")
            .args_json(serde_json::json!({
                "token": mock_token_account_id,
                "mode": "CheckToken"
            })).max_gas().transact().await.unwrap().into_result().unwrap();


        fast_bridge
    }


    async fn mint_tokens_near(token_contract: &Contract, receiver_id: &str) {
        token_contract
            .call("mint")
            .args_json(serde_json::json!({
                "account_id": receiver_id,
                "amount": format!("{}", TOKEN_SUPPLY)
            }))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap();
    }

    async fn call_aurora_contract(
        contract_address: Address,
        contract_args: Vec<u8>,
        user_account: &Account,
        engine_account: &AccountId,
        check_output: bool
    ) -> ExecutionFinalResult {
        let call_args = CallArgs::V1(FunctionCallArgsV1 {
            contract: contract_address,
            input: contract_args,
        });

        let outcome = user_account
            .call(engine_account, "call")
            .args_borsh(call_args)
            .max_gas()
            .transact()
            .await
            .unwrap();

        if check_output {
            assert!(
                outcome.failures().is_empty(),
                "Call to set failed: {:?}",
                outcome.failures()
            );
        }

        outcome
    }

    async fn engine_mint_tokens(
        user_address: Address,
        token_account: &ERC20,
        engine: &AuroraEngine,
    ) {
        let mint_args =
            token_account.create_mint_call_bytes(user_address, U256::from(TRANSFER_TOKENS_AMOUNT));
        let call_args = CallArgs::V1(FunctionCallArgsV1 {
            contract: token_account.address,
            input: mint_args.0,
        });

        let outcome = engine
            .inner
            .call("call")
            .args_borsh(call_args)
            .max_gas()
            .transact()
            .await
            .unwrap();

        assert!(
            outcome.failures().is_empty(),
            "Call to set failed: {:?}",
            outcome.failures()
        );

        let balance = engine
            .erc20_balance_of(&token_account, user_address)
            .await
            .unwrap();
        assert_eq!(balance.as_u64(), TRANSFER_TOKENS_AMOUNT);
    }
}
