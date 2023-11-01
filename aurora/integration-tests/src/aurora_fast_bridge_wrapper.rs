#[cfg(test)]
pub mod aurora_fast_bridge_wrapper {
    use crate::test_deploy::test_deploy::{
        compile_near_contracts, deploy_mock_eth_client, deploy_mock_eth_prover, deploy_mock_token,
        deploy_near_fast_bridge,
    };
    use aurora_engine_types::parameters::connector::Proof;
    use aurora_engine_v3::deposit_event::DepositedEvent;
    use aurora_sdk_integration_tests::aurora_engine_types::parameters::engine::FunctionCallArgsV2;
    use aurora_sdk_integration_tests::aurora_engine_types::types::WeiU256;
    use aurora_sdk_integration_tests::{
        aurora_engine::{self, erc20::ERC20, AuroraEngine},
        aurora_engine_types::{
            parameters::engine::{CallArgs, FunctionCallArgsV1, SubmitResult, TransactionStatus},
            types::{Address, Wei},
            U256,
        },
        ethabi,
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
    use std::rc::Rc;
    use std::time::Duration;

    const TOKEN_STORAGE_DEPOSIT: u128 = near_sdk::ONE_NEAR / 80;

    const TRANSFER_EXPIRATION_PERIOD_SEC: u64 = 30;
    const TRANSFER_TOKENS_AMOUNT: u64 = 100;
    const MAX_GAS: u64 = 300_000_000_000_000;

    pub struct AuroraFastBridgeWrapper {
        pub worker: Worker<Sandbox>,
        pub engine: AuroraEngine,
        pub wnear: Rc<Wnear>,
        pub user_account: Account,
        pub user_aurora_address: Address,
        pub aurora_fast_bridge_contract: DeployedContract,
        pub mock_token: Contract,
        pub mock_eth_client: Contract,
        pub mock_eth_prover: Contract,
        pub near_fast_bridge: Contract,
        pub aurora_mock_token: Rc<ERC20>,
    }

    impl AuroraFastBridgeWrapper {
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

            AuroraFastBridgeWrapper {
                worker,
                engine,
                wnear: Rc::new(wnear),
                user_account,
                user_aurora_address: user_address,
                aurora_fast_bridge_contract,
                mock_token,
                mock_eth_client,
                mock_eth_prover,
                near_fast_bridge,
                aurora_mock_token: Rc::new(aurora_mock_token),
            }
        }

        pub async fn init_eth(whitelist_mode: bool) -> Self {
            let worker = workspaces::sandbox().await.unwrap();
            let engine = aurora_engine::deploy_latest(&worker).await.unwrap();

            let wnear = wnear::Wnear::deploy(&worker, &engine).await.unwrap();
            let user_account = worker.dev_create_account().await.unwrap();
            let user_address =
                aurora_sdk_integration_tests::aurora_engine_sdk::types::near_account_to_evm_address(
                    user_account.id().as_bytes(),
                );

            compile_near_contracts().await;

            let mock_eth_client = deploy_mock_eth_client(&worker).await;
            let mock_eth_prover = deploy_mock_eth_prover(&worker).await;

            let near_fast_bridge = deploy_near_fast_bridge(
                &worker,
                &engine,
                &engine.inner.id().to_string(),
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

            let mock_token = deploy_mock_token(&worker, user_account.id()).await;
            let aurora_mock_token = engine.bridge_nep141(mock_token.id()).await.unwrap();

            AuroraFastBridgeWrapper {
                worker,
                engine: engine.clone(),
                wnear: Rc::new(wnear),
                user_account,
                user_aurora_address: user_address,
                aurora_fast_bridge_contract,
                mock_token: engine.inner.clone(),
                mock_eth_client,
                mock_eth_prover,
                near_fast_bridge,
                aurora_mock_token: Rc::new(aurora_mock_token),
            }
        }

        pub async fn init_second_user(aurora_fast_bridge: &AuroraFastBridgeWrapper) -> Self {
            let user_account = aurora_fast_bridge
                .worker
                .dev_create_account()
                .await
                .unwrap();
            let user_address =
                aurora_sdk_integration_tests::aurora_engine_sdk::types::near_account_to_evm_address(
                    user_account.id().as_bytes(),
                );

            Self {
                worker: aurora_fast_bridge.worker.clone(),
                engine: aurora_fast_bridge.engine.clone(),
                wnear: aurora_fast_bridge.wnear.clone(),
                user_account,
                user_aurora_address: user_address,
                aurora_fast_bridge_contract: aurora_fast_bridge.aurora_fast_bridge_contract.clone(),
                mock_token: aurora_fast_bridge.mock_token.clone(),
                mock_eth_client: aurora_fast_bridge.mock_eth_client.clone(),
                mock_eth_prover: aurora_fast_bridge.mock_eth_prover.clone(),
                near_fast_bridge: aurora_fast_bridge.near_fast_bridge.clone(),
                aurora_mock_token: aurora_fast_bridge.aurora_mock_token.clone(),
            }
        }

        pub async fn mint_wnear(&self, amount: u128) {
            self.engine
                .mint_wnear(&self.wnear, self.user_aurora_address, amount)
                .await
                .unwrap();
        }

        pub async fn aurora_storage_deposit(&self, check_result: bool) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "storageDeposit",
                    &[
                        ethabi::Token::String(self.mock_token.id().to_string()),
                        ethabi::Token::Uint(TOKEN_STORAGE_DEPOSIT.into()),
                    ],
                );

            self.call_aurora_contract(contract_args, check_result, MAX_GAS, 0)
                .await;
        }

        pub async fn approve_spend_wnear(&self) {
            approve_spend_tokens(
                &self.wnear.aurora_token,
                self.aurora_fast_bridge_contract.address,
                &self.user_account,
                &self.engine,
            )
            .await;
        }

        pub async fn call_aurora_contract(
            &self,
            contract_args: Vec<u8>,
            check_output: bool,
            gas: u64,
            attach_value: u64,
        ) {
            let res = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                check_output,
                gas,
                attach_value,
            )
            .await;

            if check_output {
                res.unwrap();
            }
        }

        pub async fn register_token(&self, check_result: bool) -> ExecutionFinalResult {
            aurora_fast_bridge_register_token(
                &self.aurora_fast_bridge_contract,
                self.mock_token.id().to_string(),
                &self.user_account,
                &self.engine,
                check_result,
            )
            .await
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

        pub async fn init_token_transfer(
            &self,
            amount: u128,
            fee_amount: u128,
            valid_till: u64,
            check_output: bool,
            gas: u64,
            attach_value: u64,
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

            self.call_aurora_contract(contract_args, check_output, gas, attach_value)
                .await;
        }

        pub async fn withdraw_from_implicit_near_account(&self, check_output: bool) {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "withdrawFromImplicitNearAccount",
                    &[
                        ethabi::Token::String(self.mock_token.id().to_string()),
                        ethabi::Token::Address(self.user_aurora_address.raw()),
                    ],
                );

            self.call_aurora_contract(contract_args, check_output, MAX_GAS, 0)
                .await;
        }

        pub async fn get_token_balance_on_aurora(&self) -> U256 {
            self.engine
                .erc20_balance_of(&self.aurora_mock_token, self.user_aurora_address)
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

        pub async fn unlock(&self, nonce: u64) {
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

            self.call_aurora_contract(contract_args, true, MAX_GAS, 0)
                .await;
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

            self.call_aurora_contract(contract_args, true, MAX_GAS, 0)
                .await;
        }

        pub async fn user_balance_in_fast_bridge_on_aurora(&self) -> Option<u64> {
            let contract_args = self
                .aurora_fast_bridge_contract
                .create_call_method_bytes_with_args(
                    "getUserBalance",
                    &[
                        ethabi::Token::String(self.mock_token.id().to_string()),
                        ethabi::Token::Address(self.user_aurora_address.raw()),
                    ],
                );
            let outcome = call_aurora_contract(
                self.aurora_fast_bridge_contract.address,
                contract_args,
                &self.user_account,
                self.engine.inner.id(),
                true,
                MAX_GAS,
                0,
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
                0,
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
                0,
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
                0,
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
                0,
            )
            .await
            .unwrap();
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
                0,
            )
            .await;

            let result = outcome.unwrap().borsh::<SubmitResult>().unwrap();
            if let TransactionStatus::Succeed(res) = result.status {
                let near_account = String::from_utf8(res.as_slice().to_vec()).unwrap();
                return Some(near_account);
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
                0,
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

        pub async fn mint_aurora_ether(&self, amount: u64) {
            self.engine
                .mint_account(self.user_aurora_address, 0, Wei::new_u64(amount))
                .await
                .unwrap();
        }

        pub async fn get_user_ether_balance(&self) -> u64 {
            return self
                .engine
                .get_balance(self.user_aurora_address)
                .await
                .unwrap()
                .raw()
                .as_u64();
        }

        pub async fn mint_ether_on_near(&self) {
            let mut user_account_bytes_str =
                format!("{:?}", self.user_account.id().to_string().as_bytes());
            user_account_bytes_str.pop();
            user_account_bytes_str.remove(0);

            //https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#:~:text=RLP%20standardizes%20the%20transfer%20of,objects%20in%20Ethereum's%20execution%20layer.
            let proof_data_eth: String = r#"{"log_index":0,"log_entry_data":[249,1,1,148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 248,66,160,209,66,67,156,39,142,37,218,217,165,7,102,241,83,208,227,210,215,191,43,209,111,194,120,28,75,212,148,178,177,90,157,160,0,0,0,0,0,0,0,0,0,0,0,0,121,24,63,219,216,14,45,138,234,26,202,162,246,123,251,138,54,212,10,141,184,166,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,39,216,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,200,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,33,"#.to_owned() +
                &user_account_bytes_str +
                r#",0,0,0,0,0],
                  "receipt_index":0,
                  "receipt_data":[],
                  "header_data":[],
                  "proof":[[]]}"#;
            let proof: Proof = serde_json::from_str(&proof_data_eth).unwrap();

            let event = DepositedEvent::from_log_entry_data(&proof.log_entry_data).unwrap();
            println!("\n==== DEPOSITED EVENT ====\n{:?}\n=====", event);

            self.engine
                .inner
                .call("deposit")
                .args_borsh(proof)
                .max_gas()
                .transact()
                .await
                .unwrap()
                .unwrap();
        }
    }

    pub async fn storage_deposit(token_contract: &Contract, account_id: &str, deposit: u128) {
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

    pub async fn aurora_fast_bridge_register_token(
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
            0,
        )
        .await
    }

    pub async fn approve_spend_tokens(
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

    pub async fn deploy_aurora_fast_bridge_contract(
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

        let constructor = forge::forge_build_with_args(
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
            &["--optimize", "--optimizer-runs", "75"],
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
            0,
        )
        .await
        .unwrap();

        return aurora_fast_bridge_impl;
    }

    pub async fn mint_tokens_near(token_contract: &Contract, amount: u64, receiver_id: &str) {
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

    pub async fn call_aurora_contract(
        contract_address: Address,
        contract_args: Vec<u8>,
        user_account: &Account,
        engine_account: &AccountId,
        check_output: bool,
        gas: u64,
        attach_value: u64,
    ) -> ExecutionFinalResult {
        let call_args = if attach_value == 0 {
            CallArgs::V1(FunctionCallArgsV1 {
                contract: contract_address,
                input: contract_args,
            })
        } else {
            CallArgs::V2(FunctionCallArgsV2 {
                contract: contract_address,
                value: WeiU256::from(U256::from(attach_value)),
                input: contract_args,
            })
        };

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

    pub async fn engine_mint_tokens(
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

    pub fn get_default_valid_till() -> u64 {
        (std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            + Duration::from_secs(TRANSFER_EXPIRATION_PERIOD_SEC).as_nanos()) as u64
    }
}
