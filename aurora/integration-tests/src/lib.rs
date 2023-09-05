pub mod test_deploy;

#[cfg(test)]
mod tests {
    use crate::test_deploy::test_deploy::{
        compile_near_contracts, deploy_mock_eth_client, deploy_mock_eth_prover, deploy_mock_token,
        deploy_near_fast_bridge, TOKEN_SUPPLY,
    };
    use aurora_sdk_integration_tests::{
        aurora_engine::{self, erc20::ERC20, AuroraEngine},
        aurora_engine_types::{
            parameters::engine::{CallArgs, FunctionCallArgsV1, SubmitResult, TransactionStatus},
            types::{Address, Wei},
            H160, U256,
        },
        ethabi, tokio,
        utils::{ethabi::DeployedContract, forge},
        wnear::{self, Wnear},
        workspaces::{
            self, network::Sandbox, result::ExecutionFinalResult, Account, AccountId, Contract,
            Worker,
        },
    };
    use fast_bridge_common::{self, EthAddress};
    use fastbridge::UnlockProof;
    use near_sdk::borsh::BorshSerialize;
    use std::path::Path;
    use std::thread::sleep;
    use std::time::Duration;

    const TOKEN_STORAGE_DEPOSIT: u128 = near_sdk::ONE_NEAR / 80;
    const NEAR_DEPOSIT: u128 = 2 * near_sdk::ONE_NEAR;
    const WNEAR_FOR_TOKENS_TRANSFERS: u128 = 100 * near_sdk::ONE_YOCTO;

    const TRANSFER_TOKENS_AMOUNT: u64 = 100;

    struct TestsInfrastructure {
        _worker: Worker<Sandbox>,
        engine: AuroraEngine,
        wnear: Wnear,
        user_account: Account,
        user_aurora_address: Address,
        aurora_fast_bridge_contract: DeployedContract,
        mock_token: Contract,
        mock_eth_client: Contract,
        _mock_eth_prover: Contract,
        near_fast_bridge: Contract,
        aurora_mock_token: ERC20,
    }

    impl TestsInfrastructure {
        pub async fn init() -> Self {
            let worker = workspaces::sandbox().await.unwrap();
            let engine = aurora_engine::deploy_latest(&worker).await.unwrap();

            let wnear = wnear::Wnear::deploy(&worker, &engine).await.unwrap();
            let user_account = worker.dev_create_account().await.unwrap();
            let user_address =
                aurora_sdk_integration_tests::aurora_engine_sdk::types::near_account_to_evm_address(
                    user_account.id().as_bytes(),
                );

            compile_near_contracts().await;
            let mock_token = deploy_mock_token(&worker, user_account.id()).await;

            let mock_eth_client = deploy_mock_eth_client(&worker).await;
            let mock_eth_prover = deploy_mock_eth_prover(&worker).await;

            let near_fast_bridge = deploy_near_fast_bridge(
                &worker,
                &mock_token.id().to_string(),
                &mock_eth_client.id().to_string(),
                &mock_eth_prover.id().to_string(),
            )
            .await;

            let aurora_fast_bridge_contract = deploy_aurora_fast_bridge_contract(
                &engine,
                &user_account,
                wnear.aurora_token.address,
                &near_fast_bridge,
            )
            .await;

            let aurora_mock_token = engine.bridge_nep141(mock_token.id()).await.unwrap();

            TestsInfrastructure {
                _worker: worker,
                engine,
                wnear,
                user_account,
                user_aurora_address: user_address,
                aurora_fast_bridge_contract,
                mock_token,
                mock_eth_client,
                _mock_eth_prover: mock_eth_prover,
                near_fast_bridge,
                aurora_mock_token,
            }
        }

        pub async fn mint_wnear(&self, user_address: Option<Address>, amount: u128) {
            self.engine
                .mint_wnear(
                    &self.wnear,
                    user_address.unwrap_or(self.user_aurora_address),
                    amount,
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
            )
            .await;
        }

        pub async fn register_token(&self, user_account: Option<Account>, check_result: bool) {
            aurora_fast_bridge_register_token(
                &self.aurora_fast_bridge_contract,
                self.aurora_mock_token.address.raw(),
                self.mock_token.id().to_string(),
                &user_account.unwrap_or(self.user_account.clone()),
                &self.engine,
                check_result,
            )
            .await;
        }

        pub async fn approve_spend_mock_tokens(&self) {
            approve_spend_tokens(
                &self.aurora_mock_token,
                self.aurora_fast_bridge_contract.address,
                &self.user_account,
                &self.engine,
            )
            .await;
        }

        pub async fn init_token_transfer(&self, amount: u128, fee_amount: u128, valid_till: u64) {
            let transfer_msg = fast_bridge_common::TransferMessage {
                valid_till,
                transfer: fast_bridge_common::TransferDataEthereum {
                    token_near: self.mock_token.id().parse().unwrap(),
                    token_eth: EthAddress(self.aurora_mock_token.address.raw().0),
                    amount: near_sdk::json_types::U128::from(amount),
                },
                fee: fast_bridge_common::TransferDataNear {
                    token: self.mock_token.id().parse().unwrap(),
                    amount: near_sdk::json_types::U128::from(fee_amount),
                },
                recipient: EthAddress(self.user_aurora_address.raw().0),
                valid_till_block_height: None,
                aurora_sender: Some(EthAddress(self.user_aurora_address.raw().0)),
            };

            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "initTokenTransfer",
                    &[ethabi::Token::Bytes(transfer_msg.try_to_vec().unwrap())],
                );

            self.call_aurora_contract(contract_args).await;
        }

        pub async fn withdraw(&self) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "withdraw",
                    &[ethabi::Token::String(self.mock_token.id().to_string())],
                );

            self.call_aurora_contract(contract_args).await;
        }

        pub async fn get_mock_token_balance_on_aurora_for(
            &self,
            user_address: Option<Address>,
        ) -> U256 {
            self.engine
                .erc20_balance_of(
                    &self.aurora_mock_token,
                    user_address.unwrap_or(self.user_aurora_address),
                )
                .await
                .unwrap()
        }

        pub async fn increment_current_eth_block(&self) {
            self.mock_eth_client
                .call("set_last_block_number")
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
            let unlock_proof: UnlockProof = Default::default();

            let unlock_proof_str = near_sdk::base64::encode(unlock_proof.try_to_vec().unwrap());

            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "unlock",
                    &[
                        ethabi::Token::Uint(U256::one()),
                        ethabi::Token::String(unlock_proof_str),
                    ],
                );

            self.call_aurora_contract(contract_args).await;
        }

        pub async fn fast_bridge_withdraw_on_near(&self) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "fastBridgeWithdrawOnNear",
                    &[
                        ethabi::Token::String(self.mock_token.id().to_string()),
                        ethabi::Token::Uint(U256::from(TRANSFER_TOKENS_AMOUNT)),
                    ],
                );

            self.call_aurora_contract(contract_args).await;
        }

        pub async fn call_aurora_contract(&self, contract_args: Vec<u8>) {
            call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
            )
            .await
            .unwrap();
        }

        pub async fn assert_user_balance_in_fast_bridge_on_aurora(
            &self,
            user_address: Option<Address>,
            expected_value: u64,
        ) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "getUserBalance",
                    &[
                        ethabi::Token::String(self.mock_token.id().to_string()),
                        ethabi::Token::Address(
                            user_address.unwrap_or(self.user_aurora_address).raw(),
                        ),
                    ],
                );
            let outcome = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
            )
            .await;

            let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
            if let TransactionStatus::Succeed(res) = result.status {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&res.as_slice()[res.len() - 8..res.len()]);
                assert_eq!(u64::from_be_bytes(buf), expected_value);
            }
        }
    }

    #[tokio::test]
    async fn test_init_token_transfer() {
        let infra = TestsInfrastructure::init().await;

        mint_tokens_near(&infra.mock_token, TOKEN_SUPPLY, infra.engine.inner.id()).await;

        infra
            .mint_wnear(None, TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;
        infra
            .mint_wnear(
                Some(infra.aurora_fast_bridge_contract.address),
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await;
        infra.approve_spend_wnear(None).await;

        infra.register_token(None, true).await;

        storage_deposit(&infra.mock_token, infra.engine.inner.id(), None).await;
        storage_deposit(&infra.mock_token, infra.near_fast_bridge.id(), None).await;
        engine_mint_tokens(
            infra.user_aurora_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;

        infra.approve_spend_mock_tokens().await;

        let balance0 = infra.get_mock_token_balance_on_aurora_for(None).await;

        let valid_till = (std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            + Duration::from_secs(30).as_nanos()) as u64;

        infra
            .init_token_transfer(TRANSFER_TOKENS_AMOUNT as u128, 0, valid_till)
            .await;
        infra
            .assert_user_balance_in_fast_bridge_on_aurora(None, 0)
            .await;

        let balance1 = infra.get_mock_token_balance_on_aurora_for(None).await;
        assert_eq!(balance1 + TRANSFER_TOKENS_AMOUNT, balance0);

        infra.withdraw().await;
        let balance2 = infra.get_mock_token_balance_on_aurora_for(None).await;
        assert_eq!(balance2, balance1);

        infra.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));
        infra
            .assert_user_balance_in_fast_bridge_on_aurora(None, 0)
            .await;
        infra.unlock().await;
        infra
            .assert_user_balance_in_fast_bridge_on_aurora(None, TRANSFER_TOKENS_AMOUNT)
            .await;
        infra.fast_bridge_withdraw_on_near().await;
        infra
            .assert_user_balance_in_fast_bridge_on_aurora(None, TRANSFER_TOKENS_AMOUNT)
            .await;
        infra.withdraw().await;

        let balance3 = infra.get_mock_token_balance_on_aurora_for(None).await;
        assert_eq!(balance3, balance0);

        infra
            .assert_user_balance_in_fast_bridge_on_aurora(None, 0)
            .await;
    }

    async fn storage_deposit(token_contract: &Contract, account_id: &str, deposit: Option<u128>) {
        let outcome = token_contract
            .call("storage_deposit")
            .args_json(serde_json::json!({ "account_id": account_id }))
            .max_gas()
            .deposit(deposit.unwrap_or(TOKEN_STORAGE_DEPOSIT))
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
        check_result: bool,
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
            check_result,
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
        let evm_call_args = token_contract.create_approve_call_bytes(spender_address, U256::MAX);
        let result = engine
            .call_evm_contract_with(
                user_account,
                token_contract.address,
                evm_call_args,
                Wei::zero(),
            )
            .await
            .unwrap();
        aurora_engine::unwrap_success(result.status).unwrap();
    }

    async fn deploy_aurora_fast_bridge_contract(
        engine: &AuroraEngine,
        user_account: &workspaces::Account,
        wnear_address: Address,
        near_fast_bridge: &Contract,
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
            &[
                "out",
                "AuroraErc20FastBridge.sol",
                "AuroraErc20FastBridge.json",
            ],
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
                ethabi::Token::Bool(false),
            ],
        );

        call_aurora_contract(
            aurora_fast_bridge_impl.address,
            contract_args,
            &user_account,
            engine.inner.id(),
            true,
        )
        .await
        .unwrap();

        return aurora_fast_bridge_impl;
    }

    async fn mint_tokens_near(token_contract: &Contract, amount: u64, receiver_id: &str) {
        token_contract
            .call("mint")
            .args_json(serde_json::json!({
                "account_id": receiver_id,
                "amount": format!("{}", amount)
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
        check_output: bool,
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
        amount: u64,
        engine: &AuroraEngine,
    ) {
        let mint_args = token_account.create_mint_call_bytes(user_address, U256::from(amount));
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
