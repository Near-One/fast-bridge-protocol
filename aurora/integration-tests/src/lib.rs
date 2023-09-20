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
            U256,
        },
        ethabi, tokio,
        utils::{ethabi::DeployedContract, forge},
        wnear::{self, Wnear},
        workspaces::{
            self, network::Sandbox, result::ExecutionFinalResult, Account, AccountId, Contract,
            Worker,
        },
    };
    use near_sdk::borsh::BorshSerialize;
    use fast_bridge_common::{self, EthAddress};
    use fastbridge::UnlockProof;
    use aurora_engine_types::parameters::connector::Proof;
    use aurora_engine_types::parameters::connector::LogEntry;
    use aurora_engine_v3::deposit_event::DepositedEvent;
    use std::path::Path;
    use std::thread::sleep;
    use std::time::Duration;
    use aurora_engine_types::{H160, H256};
    use aurora_sdk_integration_tests::aurora_engine_types::parameters::engine::FunctionCallArgsV2;
    use aurora_sdk_integration_tests::aurora_engine_types::types::WeiU256;
    use aurora_sdk_integration_tests::ethabi::Log;
    use hex::FromHex;

    const TOKEN_STORAGE_DEPOSIT: u128 = near_sdk::ONE_NEAR / 80;
    const NEAR_DEPOSIT: u128 = 2 * near_sdk::ONE_NEAR;
    const WNEAR_FOR_TOKENS_TRANSFERS: u128 = 100 * near_sdk::ONE_YOCTO;

    const TRANSFER_EXPIRATION_PERIOD_SEC: u64 = 30;
    const TRANSFER_TOKENS_AMOUNT: u64 = 100;
    const MAX_GAS: u64 = 300_000_000_000_000;

    struct TestsInfrastructure {
        worker: Worker<Sandbox>,
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
        pub async fn init(whitelist_mode: bool) -> Self {
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
                &engine,
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
                whitelist_mode,
            )
            .await;

            let aurora_mock_token = engine.bridge_nep141(mock_token.id()).await.unwrap();

            TestsInfrastructure {
                worker: worker,
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

        pub async fn mint_wnear(&self, user_address: Address, amount: u128) {
            self.engine
                .mint_wnear(&self.wnear, user_address, amount)
                .await
                .unwrap();
        }

        pub async fn aurora_storage_deposit(&self, user_account: &Account, check_result: bool) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "storageDeposit",
                    &[
                        ethabi::Token::String(self.mock_token.id().to_string()),
                        ethabi::Token::Uint(TOKEN_STORAGE_DEPOSIT.into()),
                    ],
                );

            call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                user_account,
                self.engine.inner.id(),
                check_result,
                MAX_GAS,
            )
            .await
            .unwrap();
        }

        pub async fn aurora_storage_deposit_ether(&self, user_account: &Account, check_result: bool) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "storageDeposit",
                    &[
                        ethabi::Token::String(self.engine.inner.id().to_string()),
                        ethabi::Token::Uint(TOKEN_STORAGE_DEPOSIT.into()),
                    ],
                );

            call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                user_account,
                self.engine.inner.id(),
                check_result,
                MAX_GAS,
            )
                .await
                .unwrap();
        }

        pub async fn approve_spend_wnear(&self, user_account: &Account) {
            approve_spend_tokens(
                &self.wnear.aurora_token,
                self.aurora_fast_bridge_contract.address,
                &user_account,
                &self.engine,
            )
            .await;
        }

        pub async fn register_token(
            &self,
            user_account: &Account,
            check_result: bool,
        ) -> ExecutionFinalResult {
            aurora_fast_bridge_register_token(
                &self.aurora_fast_bridge_contract,
                self.mock_token.id().to_string(),
                user_account,
                &self.engine,
                check_result,
            )
            .await
        }

        pub async fn register_eth_token(
            &self,
            user_account: &Account,
            check_result: bool,
        ) -> ExecutionFinalResult {
            let contract_args = self.aurora_fast_bridge_contract.create_call_method_bytes_with_args(
                "registerToken",
                &[ethabi::Token::String(self.engine.inner.id().to_string())],
            );

            call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                user_account,
                self.engine.inner.id(),
                check_result,
                MAX_GAS,
            )
                .await
        }

        pub async fn approve_spend_mock_tokens(&self, user_account: &Account) {
            approve_spend_tokens(
                &self.aurora_mock_token,
                self.aurora_fast_bridge_contract.address,
                user_account,
                &self.engine,
            )
            .await;
        }

        pub async fn init_token_transfer(
            &self,
            amount: u128,
            fee_amount: u128,
            valid_till: u64,
            user_address: &Address,
            user_account: &Account,
            check_output: bool,
            gas: u64,
        ) {
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
                recipient: EthAddress(user_address.raw().0),
                valid_till_block_height: None,
                aurora_sender: Some(EthAddress(user_address.raw().0)),
            };

            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "initTokenTransfer",
                    &[ethabi::Token::Bytes(transfer_msg.try_to_vec().unwrap())],
                );

            self.call_aurora_contract(contract_args, user_account, check_output, gas)
                .await;
        }

        pub async fn init_token_transfer_eth(
            &self,
            amount: u128,
            fee_amount: u128,
            valid_till: u64,
            user_address: &Address,
            user_account: &Account,
            check_output: bool,
            gas: u64,
        ) {
            let transfer_msg = fast_bridge_common::TransferMessage {
                valid_till,
                transfer: fast_bridge_common::TransferDataEthereum {
                    token_near: self.engine.inner.id().parse().unwrap(),
                    token_eth: EthAddress(Address::zero().raw().0),
                    amount: near_sdk::json_types::U128::from(amount),
                },
                fee: fast_bridge_common::TransferDataNear {
                    token: self.engine.inner.id().parse().unwrap(),
                    amount: near_sdk::json_types::U128::from(fee_amount),
                },
                recipient: EthAddress(user_address.raw().0),
                valid_till_block_height: None,
                aurora_sender: Some(EthAddress(user_address.raw().0)),
            };

            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "initTokenTransfer",
                    &[ethabi::Token::Bytes(transfer_msg.try_to_vec().unwrap())],
                );


            let call_args = CallArgs::V2(FunctionCallArgsV2 {
                contract: self.aurora_fast_bridge_contract.address,
                value: WeiU256::from(U256::from(TRANSFER_TOKENS_AMOUNT)),
                input: contract_args,
            });

            let outcome = user_account
                .call(self.engine.inner.id(), "call")
                .args_borsh(call_args)
                .gas(gas)
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
        }

        pub async fn withdraw_from_implicit_near_account(
            &self,
            user_account: &Account,
            user_address: &Address,
            check_output: bool,
        ) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "withdrawFromImplicitNearAccount",
                    &[
                        ethabi::Token::String(self.mock_token.id().to_string()),
                        ethabi::Token::Address(user_address.raw()),
                    ],
                );

            self.call_aurora_contract(contract_args, user_account, check_output, MAX_GAS)
                .await;
        }

        pub async fn withdraw_eth_from_implicit_near_account(
            &self,
            user_account: &Account,
            user_address: &Address,
            check_output: bool,
        ) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "withdrawFromImplicitNearAccount",
                    &[
                        ethabi::Token::String(self.engine.inner.id().to_string()),
                        ethabi::Token::Address(user_address.raw()),
                    ],
                );

            self.call_aurora_contract(contract_args, user_account, check_output, MAX_GAS)
                .await;
        }

        pub async fn get_mock_token_balance_on_aurora_for(&self, user_address: Address) -> U256 {
            self.engine
                .erc20_balance_of(&self.aurora_mock_token, user_address)
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

        pub async fn unlock(&self, user_account: &Account, nonce: u64) {
            let unlock_proof: UnlockProof = Default::default();

            let unlock_proof_str = near_sdk::base64::encode(unlock_proof.try_to_vec().unwrap());

            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "unlock",
                    &[
                        ethabi::Token::Uint(U256::from(nonce)),
                        ethabi::Token::String(unlock_proof_str),
                    ],
                );

            self.call_aurora_contract(contract_args, user_account, true, MAX_GAS)
                .await;
        }

        pub async fn fast_bridge_withdraw_on_near(&self, user_account: &Account) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "fastBridgeWithdrawOnNear",
                    &[
                        ethabi::Token::String(self.mock_token.id().to_string()),
                        ethabi::Token::Uint(U256::from(TRANSFER_TOKENS_AMOUNT)),
                    ],
                );

            self.call_aurora_contract(contract_args, user_account, true, MAX_GAS)
                .await;
        }

        pub async fn fast_bridge_withdraw_eth_on_near(&self, user_account: &Account) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "fastBridgeWithdrawOnNear",
                    &[
                        ethabi::Token::String(self.engine.inner.id().to_string()),
                        ethabi::Token::Uint(U256::from(TRANSFER_TOKENS_AMOUNT)),
                    ],
                );

            self.call_aurora_contract(contract_args, user_account, true, MAX_GAS)
                .await;
        }

        pub async fn call_aurora_contract(
            &self,
            contract_args: Vec<u8>,
            user_account: &Account,
            check_output: bool,
            gas: u64,
        ) {
            let res = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                user_account,
                self.engine.inner.id(),
                check_output,
                gas,
            )
            .await;

            if check_output {
                res.unwrap();
            }
        }

        pub async fn user_balance_in_fast_bridge_on_aurora(
            &self,
            user_address: &Address,
        ) -> Option<u64> {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "getUserBalance",
                    &[
                        ethabi::Token::String(self.mock_token.id().to_string()),
                        ethabi::Token::Address(user_address.raw()),
                    ],
                );
            let outcome = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
                MAX_GAS,
            )
            .await;

            let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
            if let TransactionStatus::Succeed(res) = result.status {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&res.as_slice()[res.len() - 8..res.len()]);
                return Some(u64::from_be_bytes(buf));
            }

            return None;
        }


        pub async fn user_eth_balance_in_fast_bridge_on_aurora(
            &self,
            user_address: &Address,
        ) -> Option<u64> {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "getUserBalance",
                    &[
                        ethabi::Token::String(self.engine.inner.id().to_string()),
                        ethabi::Token::Address(user_address.raw()),
                    ],
                );
            let outcome = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
                MAX_GAS,
            )
                .await;

            let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
            if let TransactionStatus::Succeed(res) = result.status {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&res.as_slice()[res.len() - 8..res.len()]);
                return Some(u64::from_be_bytes(buf));
            }

            return None;
        }

        pub async fn user_balance_in_fast_bridge_on_aurora_ether(
            &self,
            user_address: &Address,
        ) -> Option<u64> {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "getUserBalance",
                    &[
                        ethabi::Token::String(self.engine.inner.id().to_string()),
                        ethabi::Token::Address(user_address.raw()),
                    ],
                );
            let outcome = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
                MAX_GAS,
            )
                .await;

            let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
            if let TransactionStatus::Succeed(res) = result.status {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&res.as_slice()[res.len() - 8..res.len()]);
                return Some(u64::from_be_bytes(buf));
            }

            return None;
        }

        pub async fn get_token_aurora_address(&self) -> Option<[u8; 20]> {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "getTokenAuroraAddress",
                    &[ethabi::Token::String(self.mock_token.id().to_string())],
                );
            let outcome = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
                MAX_GAS,
            )
            .await;

            let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
            if let TransactionStatus::Succeed(res) = result.status {
                let mut buf = [0u8; 20];
                buf.copy_from_slice(&res.as_slice()[res.len() - 20..res.len()]);
                return Some(buf);
            }

            return None;
        }

        pub async fn get_implicit_near_account_id_for_self(&self) -> Option<String> {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args("getImplicitNearAccountIdForSelf", &[]);
            let outcome = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
                MAX_GAS,
            )
            .await;

            let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
            if let TransactionStatus::Succeed(res) = result.status {
                let near_account = String::from_utf8(res.as_slice().to_vec()).unwrap();
                return Some(near_account);
            }

            return None;
        }

        pub async fn is_user_whitelisted(&self, user_address: Address) -> Option<bool> {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "isUserWhitelisted",
                    &[ethabi::Token::Address(user_address.raw())],
                );
            let outcome = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
                MAX_GAS,
            )
            .await;

            let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();

            if let TransactionStatus::Succeed(res) = result.status {
                return Some(res[res.len() - 1] != 0);
            }

            return None;
        }

        pub async fn is_storage_registered(&self, token_account_id: String) -> Option<bool> {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "isStorageRegistered",
                    &[ethabi::Token::String(token_account_id)],
                );
            let outcome = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
                MAX_GAS,
            )
                .await;

            let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();

            if let TransactionStatus::Succeed(res) = result.status {
                return Some(res[res.len() - 1] != 0);
            }

            return None;
        }

        pub async fn set_whitelist_mode(&self, is_enabled: bool) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "setWhitelistMode",
                    &[ethabi::Token::Bool(is_enabled)],
                );
            call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
                MAX_GAS,
            )
            .await
            .unwrap();
        }

        pub async fn set_whitelist_mode_for_user(&self, users: Vec<Address>, states: Vec<bool>) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "setWhitelistModeForUsers",
                    &[
                        ethabi::Token::Array(
                            users
                                .into_iter()
                                .map(|x| ethabi::Token::Address(x.raw()))
                                .collect(),
                        ),
                        ethabi::Token::Array(
                            states.into_iter().map(|x| ethabi::Token::Bool(x)).collect(),
                        ),
                    ],
                );

            call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
                MAX_GAS,
            )
            .await
            .unwrap();
        }

        pub async fn mint_ether(&self) {
            let mut user_account_bytes_str = format!("{:?}", self.user_account.id().to_string().as_bytes());
            user_account_bytes_str.pop();
            user_account_bytes_str.remove(0);

            println!("{}", &format!("{:?}",  user_account_bytes_str));


            //https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#:~:text=RLP%20standardizes%20the%20transfer%20of,objects%20in%20Ethereum's%20execution%20layer.
            let PROOF_DATA_ETH: String = r#"{"log_index":0,"log_entry_data":[249,1,1,148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,166,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,39,216,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,200,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,33,"#.to_owned() +
            &user_account_bytes_str +
            r#",0,0,0,0,0],
            "receipt_index":0,
            "receipt_data":[],
            "header_data":[],
            "proof":[[]]}"#;
            let proof: Proof = serde_json::from_str(&PROOF_DATA_ETH).unwrap();

            println!("eth_connector.root as bytes: {:?}", "eth_connector.root".as_bytes());
            println!("to string: {:?}", std::str::from_utf8(&[101,116,104,95,99,111,110,110,101,99,116,111,114,46,114,111,111,116,58,56,57,49,66,50,55,52,57,50,51,56,66,50,55,102,70,53,56,101,57,53,49,48,56,56,101,53,53,98,48,52,100,101,55,49,68,99,51,55,52]));

            println!("user account as bytes: {:?}", self.user_account.id().to_string().as_bytes());

            let event = DepositedEvent::from_log_entry_data(&proof.log_entry_data).unwrap();
            println!("\n==== DEPOSITED EVENT ====\n{:?}\n=====", event);

            println!("{:?}", self.engine.inner.call("deposit").args_borsh(proof).max_gas().transact().await.unwrap());
        }

        pub async fn mint_aurora_ether(&self) {
            self.engine.mint_account(self.user_aurora_address, 0, Wei::new_u64(TRANSFER_TOKENS_AMOUNT)).await.unwrap();
        }

        pub async fn get_user_ether_balance(&self) -> u64 {
            return self.engine.get_balance(self.user_aurora_address).await.unwrap().raw().as_u64();
        }
    }

    #[tokio::test]
    async fn test_init_token_transfer() {
        let infra = TestsInfrastructure::init(false).await;

        mint_tokens_near(&infra.mock_token, TOKEN_SUPPLY, infra.engine.inner.id()).await;

        infra
            .mint_wnear(
                infra.user_aurora_address,
                TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT,
            )
            .await;
        infra
            .mint_wnear(
                infra.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await;
        infra.approve_spend_wnear(&infra.user_account).await;

        infra
            .register_token(&infra.user_account, true)
            .await
            .unwrap();
        infra
            .aurora_storage_deposit(&infra.user_account, true)
            .await;
        assert_eq!(
            infra.get_token_aurora_address().await.unwrap(),
            infra.aurora_mock_token.address.raw().0
        );

        storage_deposit(
            &infra.mock_token,
            infra.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        storage_deposit(
            &infra.mock_token,
            infra.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;

        engine_mint_tokens(
            infra.user_aurora_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;

        infra.approve_spend_mock_tokens(&infra.user_account).await;

        let balance0 = infra
            .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
            .await;

        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &infra.user_aurora_address,
                &infra.user_account,
                true,
                MAX_GAS,
            )
            .await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );

        let balance1 = infra
            .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
            .await;
        assert_eq!(balance1 + TRANSFER_TOKENS_AMOUNT, balance0);

        infra
            .withdraw_from_implicit_near_account(
                &infra.user_account,
                &infra.user_aurora_address,
                true,
            )
            .await;
        let balance2 = infra
            .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
            .await;
        assert_eq!(balance2, balance1);

        infra.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );

        infra.unlock(&infra.user_account, 1).await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .fast_bridge_withdraw_on_near(&infra.user_account)
            .await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .withdraw_from_implicit_near_account(
                &infra.user_account,
                &infra.user_aurora_address,
                true,
            )
            .await;

        let balance3 = infra
            .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
            .await;
        assert_eq!(balance3, balance0);

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn test_double_spend() {
        let infra = TestsInfrastructure::init(false).await;
        mint_tokens_near(&infra.mock_token, TOKEN_SUPPLY, infra.engine.inner.id()).await;

        let second_user_account = infra.worker.dev_create_account().await.unwrap();
        let second_user_address =
            aurora_sdk_integration_tests::aurora_engine_sdk::types::near_account_to_evm_address(
                second_user_account.id().as_bytes(),
            );

        infra
            .mint_wnear(
                infra.user_aurora_address,
                TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT,
            )
            .await;

        infra
            .mint_wnear(
                infra.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await;
        infra.approve_spend_wnear(&infra.user_account).await;
        infra
            .register_token(&infra.user_account, true)
            .await
            .unwrap();
        infra
            .aurora_storage_deposit(&infra.user_account, true)
            .await;

        storage_deposit(
            &infra.mock_token,
            infra.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        storage_deposit(
            &infra.mock_token,
            infra.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;

        engine_mint_tokens(
            infra.user_aurora_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;

        engine_mint_tokens(
            second_user_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;

        infra.approve_spend_mock_tokens(&infra.user_account).await;
        infra
            .approve_spend_mock_tokens(&second_user_account.clone())
            .await;

        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &infra.user_aurora_address,
                &infra.user_account,
                true,
                MAX_GAS,
            )
            .await;
        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &second_user_address,
                &second_user_account,
                true,
                MAX_GAS,
            )
            .await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&second_user_address)
                .await
                .unwrap(),
            0
        );

        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            0
        );
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            0
        );

        infra.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&second_user_address)
                .await
                .unwrap(),
            0
        );

        infra.unlock(&infra.user_account, 1).await;
        infra.unlock(&second_user_account, 2).await;

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&second_user_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            0
        );
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            0
        );

        infra
            .fast_bridge_withdraw_on_near(&infra.user_account)
            .await;
        infra
            .fast_bridge_withdraw_on_near(&second_user_account)
            .await;

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&second_user_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            0
        );
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            0
        );

        infra
            .withdraw_from_implicit_near_account(
                &infra.user_account,
                &infra.user_aurora_address,
                true,
            )
            .await;
        infra
            .withdraw_from_implicit_near_account(
                &infra.user_account,
                &infra.user_aurora_address,
                true,
            )
            .await;

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&second_user_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            0
        );

        infra
            .withdraw_from_implicit_near_account(&second_user_account, &second_user_address, true)
            .await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&second_user_address)
                .await
                .unwrap(),
            0
        );

        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
    }

    #[tokio::test]
    async fn test_token_transfer_fail() {
        let infra = TestsInfrastructure::init(false).await;
        mint_tokens_near(&infra.mock_token, TOKEN_SUPPLY, infra.engine.inner.id()).await;
        infra
            .mint_wnear(
                infra.user_aurora_address,
                TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT,
            )
            .await;
        infra
            .mint_wnear(
                infra.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await;
        infra.approve_spend_wnear(&infra.user_account).await;
        infra
            .register_token(&infra.user_account, true)
            .await
            .unwrap();
        infra
            .aurora_storage_deposit(&infra.user_account, true)
            .await;

        storage_deposit(
            &infra.mock_token,
            infra.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        engine_mint_tokens(
            infra.user_aurora_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;
        infra.approve_spend_mock_tokens(&infra.user_account).await;
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &infra.user_aurora_address,
                &infra.user_account,
                false,
                MAX_GAS,
            )
            .await;
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            0
        );
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .withdraw_from_implicit_near_account(
                &infra.user_account,
                &infra.user_aurora_address,
                true,
            )
            .await;
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );

        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &infra.user_aurora_address,
                &infra.user_account,
                false,
                200_000_000_000_000,
            )
            .await;

        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn test_withdraw_without_fast_bridge_withdraw_on_near() {
        let infra = TestsInfrastructure::init(false).await;
        mint_tokens_near(&infra.mock_token, TOKEN_SUPPLY, infra.engine.inner.id()).await;

        let second_user_account = infra.worker.dev_create_account().await.unwrap();
        let second_user_address =
            aurora_sdk_integration_tests::aurora_engine_sdk::types::near_account_to_evm_address(
                second_user_account.id().as_bytes(),
            );

        infra
            .mint_wnear(
                infra.user_aurora_address,
                TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT,
            )
            .await;
        infra
            .mint_wnear(
                infra.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await;
        infra.approve_spend_wnear(&infra.user_account).await;
        infra
            .register_token(&infra.user_account, true)
            .await
            .unwrap();
        infra
            .aurora_storage_deposit(&infra.user_account, true)
            .await;

        storage_deposit(
            &infra.mock_token,
            infra.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        storage_deposit(
            &infra.mock_token,
            infra.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;

        engine_mint_tokens(
            infra.user_aurora_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;

        engine_mint_tokens(
            second_user_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;

        infra.approve_spend_mock_tokens(&infra.user_account).await;
        infra
            .approve_spend_mock_tokens(&second_user_account.clone())
            .await;

        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &infra.user_aurora_address,
                &infra.user_account,
                true,
                MAX_GAS,
            )
            .await;
        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &second_user_address,
                &second_user_account,
                true,
                MAX_GAS,
            )
            .await;

        infra.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));

        infra.unlock(&infra.user_account, 1).await;
        infra.unlock(&second_user_account, 2).await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .withdraw_from_implicit_near_account(
                &infra.user_account,
                &infra.user_aurora_address,
                false,
            )
            .await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            0
        );

        infra
            .fast_bridge_withdraw_on_near(&infra.user_account)
            .await;
        infra
            .withdraw_from_implicit_near_account(&second_user_account, &second_user_address, false)
            .await;
        infra
            .withdraw_from_implicit_near_account(
                &infra.user_account,
                &infra.user_aurora_address,
                false,
            )
            .await;

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            0
        );

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&second_user_address)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .fast_bridge_withdraw_on_near(&infra.user_account)
            .await;
        infra
            .withdraw_from_implicit_near_account(
                &infra.user_account,
                &infra.user_aurora_address,
                false,
            )
            .await;

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
    }

    #[tokio::test]
    async fn get_implicit_near_account_id_for_self_test() {
        let infra = TestsInfrastructure::init(false).await;
        mint_tokens_near(&infra.mock_token, TOKEN_SUPPLY, infra.engine.inner.id()).await;
        infra
            .mint_wnear(
                infra.user_aurora_address,
                TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT,
            )
            .await;
        infra.approve_spend_wnear(&infra.user_account).await;

        let output = infra.register_token(&infra.user_account, true).await;
        infra
            .aurora_storage_deposit(&infra.user_account, true)
            .await;

        assert!(infra
            .get_implicit_near_account_id_for_self()
            .await
            .unwrap()
            .contains(&output.receipt_outcomes()[1].executor_id.to_string()));
    }

    #[tokio::test]
    async fn whitelist_mode_test() {
        let infra = TestsInfrastructure::init(true).await;
        let second_user_account = infra.worker.dev_create_account().await.unwrap();
        let second_user_address =
            aurora_sdk_integration_tests::aurora_engine_sdk::types::near_account_to_evm_address(
                second_user_account.id().as_bytes(),
            );

        assert_eq!(
            infra.is_user_whitelisted(second_user_address).await,
            Some(false)
        );
        assert_eq!(
            infra.is_user_whitelisted(infra.user_aurora_address).await,
            Some(true)
        );

        mint_tokens_near(&infra.mock_token, TOKEN_SUPPLY, infra.engine.inner.id()).await;
        infra
            .mint_wnear(
                infra.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await;
        storage_deposit(
            &infra.mock_token,
            infra.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        storage_deposit(
            &infra.mock_token,
            infra.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;

        infra
            .mint_wnear(
                infra.user_aurora_address,
                TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT,
            )
            .await;
        infra
            .mint_wnear(second_user_address, TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;

        infra.approve_spend_wnear(&infra.user_account).await;
        infra.approve_spend_wnear(&second_user_account).await;

        infra
            .register_token(&infra.user_account, true)
            .await
            .unwrap();
        infra
            .aurora_storage_deposit(&infra.user_account, true)
            .await;

        engine_mint_tokens(
            infra.user_aurora_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;
        engine_mint_tokens(
            second_user_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;

        infra.approve_spend_mock_tokens(&infra.user_account).await;
        infra.approve_spend_mock_tokens(&second_user_account).await;

        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &second_user_address,
                &second_user_account,
                false,
                MAX_GAS,
            )
            .await;
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &infra.user_aurora_address,
                &infra.user_account,
                true,
                MAX_GAS,
            )
            .await;
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            0
        );

        infra.set_whitelist_mode(false).await;
        assert_eq!(
            infra.is_user_whitelisted(second_user_address).await,
            Some(true)
        );
        assert_eq!(
            infra.is_user_whitelisted(infra.user_aurora_address).await,
            Some(true)
        );

        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &second_user_address,
                &second_user_account,
                true,
                MAX_GAS,
            )
            .await;
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            0
        );

        infra.set_whitelist_mode(true).await;
        infra
            .set_whitelist_mode_for_user(
                vec![infra.user_aurora_address, second_user_address],
                vec![false, true],
            )
            .await;

        assert_eq!(
            infra.is_user_whitelisted(second_user_address).await,
            Some(true)
        );
        assert_eq!(
            infra.is_user_whitelisted(infra.user_aurora_address).await,
            Some(false)
        );

        engine_mint_tokens(
            infra.user_aurora_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;
        engine_mint_tokens(
            second_user_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
        .await;

        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &second_user_address,
                &second_user_account,
                false,
                MAX_GAS,
            )
            .await;
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(second_user_address)
                .await
                .as_u64(),
            0
        );

        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &infra.user_aurora_address,
                &infra.user_account,
                true,
                MAX_GAS,
            )
            .await;
        assert_eq!(
            infra
                .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
    }

    #[tokio::test]
    async fn withdraw_by_other_user() {
        let infra = TestsInfrastructure::init(false).await;

        mint_tokens_near(&infra.mock_token, TOKEN_SUPPLY, infra.engine.inner.id()).await;

        infra
            .mint_wnear(
                infra.user_aurora_address,
                TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT,
            )
            .await;
        infra
            .mint_wnear(
                infra.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await;
        infra.approve_spend_wnear(&infra.user_account).await;

        infra
            .register_token(&infra.user_account, true)
            .await
            .unwrap();

        infra
            .aurora_storage_deposit(&infra.user_account, true)
            .await;

        assert_eq!(
            infra.get_token_aurora_address().await.unwrap(),
            infra.aurora_mock_token.address.raw().0
        );

        storage_deposit(
            &infra.mock_token,
            infra.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
            .await;
        storage_deposit(
            &infra.mock_token,
            infra.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
            .await;

        engine_mint_tokens(
            infra.user_aurora_address,
            &infra.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &infra.engine,
        )
            .await;

        infra.approve_spend_mock_tokens(&infra.user_account).await;

        let balance0 = infra
            .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
            .await;

        infra
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &infra.user_aurora_address,
                &infra.user_account,
                true,
                MAX_GAS,
            )
            .await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );

        let balance1 = infra
            .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
            .await;
        assert_eq!(balance1 + TRANSFER_TOKENS_AMOUNT, balance0);

        infra.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );

        let second_user_account = infra.worker.dev_create_account().await.unwrap();

        infra.unlock(&second_user_account, 1).await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .fast_bridge_withdraw_on_near(&second_user_account)
            .await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .withdraw_from_implicit_near_account(
                &second_user_account,
                &infra.user_aurora_address,
                true,
            )
            .await;

        let balance3 = infra
            .get_mock_token_balance_on_aurora_for(infra.user_aurora_address)
            .await;
        assert_eq!(balance3, balance0);

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn test_transfer_ether() {
        let infra = TestsInfrastructure::init(false).await;

        infra
            .mint_wnear(
                infra.user_aurora_address,
                TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT,
            )
            .await;

        infra
            .mint_wnear(
                infra.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await;
        infra.approve_spend_wnear(&infra.user_account).await;

        infra
            .register_eth_token(&infra.user_account, true)
            .await
            .unwrap();

        infra
            .aurora_storage_deposit_ether(&infra.user_account, true)
            .await;

        assert_eq!(
            infra.is_storage_registered(infra.engine.inner.id().to_string()).await.unwrap(),
            true
        );

        storage_deposit(
            &infra.engine.inner,
            infra.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
            .await;
        storage_deposit(
            &infra.engine.inner,
            infra.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
            .await;

        //infra.mint_ether().await;
        infra.mint_aurora_ether().await;

        println!("{:?}", infra.engine.inner.id());
        println!("{:?}", infra.user_account);
        println!("{:?}", infra.aurora_fast_bridge_contract.address);
        println!("{:?}", infra.wnear.inner.id());
        println!("{:?}", infra.mock_token.id());
        println!("{:?}", infra.mock_eth_client.id());
        println!("{:?}", infra.near_fast_bridge.id());

        println!("{:?}", infra.engine.inner.call("ft_total_supply").max_gas().transact().await.unwrap());

        let balance0 = infra.get_user_ether_balance().await;
        assert_eq!(balance0, TRANSFER_TOKENS_AMOUNT);

        infra
            .init_token_transfer_eth(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                &infra.user_aurora_address,
                &infra.user_account,
                true,
                MAX_GAS,
            )
            .await;

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora_ether(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );

        let balance1 = infra.get_user_ether_balance().await;
        assert_eq!(balance1 + TRANSFER_TOKENS_AMOUNT, balance0);

        infra
            .withdraw_from_implicit_near_account(
                &infra.user_account,
                &infra.user_aurora_address,
                true,
            )
            .await;
        let balance2 = infra.get_user_ether_balance().await;
        assert_eq!(balance2, balance1);

        infra.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora_ether(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );

        infra.unlock(&infra.user_account, 1).await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora_ether(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .fast_bridge_withdraw_eth_on_near(&infra.user_account)
            .await;
        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora_ether(&infra.user_aurora_address)
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        infra
            .withdraw_eth_from_implicit_near_account(
                &infra.user_account,
                &infra.user_aurora_address,
                true,
            )
            .await;

        let balance3 = infra.get_user_ether_balance().await;
        assert_eq!(balance3, balance0);

        assert_eq!(
            infra
                .user_balance_in_fast_bridge_on_aurora_ether(&infra.user_aurora_address)
                .await
                .unwrap(),
            0
        );
    }

    async fn storage_deposit(token_contract: &Contract, account_id: &str, deposit: u128) {
        let outcome = token_contract
            .call("storage_deposit")
            .args_json(serde_json::json!({ "account_id": account_id }))
            .max_gas()
            .deposit(deposit)
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
        near_mock_token_account_id: String,
        user_account: &Account,
        engine: &AuroraEngine,
        check_result: bool,
    ) -> ExecutionFinalResult {
        let contract_args = aurora_fast_bridge.create_call_method_bytes_with_args(
            "registerToken",
            &[ethabi::Token::String(near_mock_token_account_id)],
        );

        call_aurora_contract(
            aurora_fast_bridge.address,
            contract_args,
            user_account,
            engine.inner.id(),
            check_result,
            MAX_GAS,
        )
        .await
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
        whitelist_mode: bool,
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
                ethabi::Token::Bool(whitelist_mode),
            ],
        );

        call_aurora_contract(
            aurora_fast_bridge_impl.address,
            contract_args,
            &user_account,
            engine.inner.id(),
            true,
            MAX_GAS,
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
        gas: u64,
    ) -> ExecutionFinalResult {
        let call_args = CallArgs::V1(FunctionCallArgsV1 {
            contract: contract_address,
            input: contract_args,
        });

        let outcome = user_account
            .call(engine_account, "call")
            .args_borsh(call_args)
            .gas(gas)
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

    fn get_default_valid_till() -> u64 {
        (std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            + Duration::from_secs(TRANSFER_EXPIRATION_PERIOD_SEC).as_nanos()) as u64
    }
}
