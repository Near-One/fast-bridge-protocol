pub mod test_deploy;
pub mod aurora_fast_bridge_wrapper;

#[cfg(test)]
mod tests {
    use crate::test_deploy::test_deploy::TOKEN_SUPPLY;
    use aurora_sdk_integration_tests::tokio;
    use std::thread::sleep;
    use std::time::Duration;

    use crate::aurora_fast_bridge_wrapper::aurora_fast_bridge_wrapper::TestsInfrastructure;
    use crate::aurora_fast_bridge_wrapper::aurora_fast_bridge_wrapper::get_default_valid_till;
    use crate::aurora_fast_bridge_wrapper::aurora_fast_bridge_wrapper::storage_deposit;
    use crate::aurora_fast_bridge_wrapper::aurora_fast_bridge_wrapper::engine_mint_tokens;
    use crate::aurora_fast_bridge_wrapper::aurora_fast_bridge_wrapper::mint_tokens_near;

    const TOKEN_STORAGE_DEPOSIT: u128 = near_sdk::ONE_NEAR / 80;
    const NEAR_DEPOSIT: u128 = 2 * near_sdk::ONE_NEAR;
    const WNEAR_FOR_TOKENS_TRANSFERS: u128 = 100 * near_sdk::ONE_YOCTO;

    const TRANSFER_TOKENS_AMOUNT: u64 = 100;
    const MAX_GAS: u64 = 300_000_000_000_000;

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
}
