pub mod aurora_fast_bridge_wrapper;
pub mod test_deploy;

#[cfg(test)]
mod tests {
    use crate::test_deploy::test_deploy::TOKEN_SUPPLY;
    use aurora_sdk_integration_tests::tokio;
    use std::thread::sleep;
    use std::time::Duration;

    use crate::aurora_fast_bridge_wrapper::aurora_fast_bridge_wrapper::engine_mint_tokens;
    use crate::aurora_fast_bridge_wrapper::aurora_fast_bridge_wrapper::get_default_valid_till;
    use crate::aurora_fast_bridge_wrapper::aurora_fast_bridge_wrapper::mint_tokens_near;
    use crate::aurora_fast_bridge_wrapper::aurora_fast_bridge_wrapper::storage_deposit;
    use crate::aurora_fast_bridge_wrapper::aurora_fast_bridge_wrapper::AuroraFastBridgeWrapper;

    const TOKEN_STORAGE_DEPOSIT: u128 = near_sdk::ONE_NEAR / 80;
    const NEAR_DEPOSIT: u128 = 2 * near_sdk::ONE_NEAR;
    const WNEAR_FOR_TOKENS_TRANSFERS: u128 = 100 * near_sdk::ONE_YOCTO;

    const TRANSFER_TOKENS_AMOUNT: u64 = 100;
    const MAX_GAS: u64 = 300_000_000_000_000;

    #[tokio::test]
    async fn test_init_token_transfer() {
        let aurora_fast_bridge = AuroraFastBridgeWrapper::init(false).await;

        mint_tokens_near(
            &aurora_fast_bridge.mock_token,
            TOKEN_SUPPLY,
            aurora_fast_bridge.engine.inner.id(),
        )
        .await;

        aurora_fast_bridge
            .mint_wnear(TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;

        aurora_fast_bridge
            .engine
            .mint_wnear(
                &aurora_fast_bridge.wnear,
                aurora_fast_bridge.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await
            .unwrap();

        aurora_fast_bridge.approve_spend_wnear().await;

        aurora_fast_bridge.register_token(true).await.unwrap();
        aurora_fast_bridge.aurora_storage_deposit(true).await;
        assert_eq!(
            aurora_fast_bridge.get_token_aurora_address().await.unwrap(),
            aurora_fast_bridge.aurora_mock_token.address.raw().0
        );

        storage_deposit(
            &aurora_fast_bridge.mock_token,
            aurora_fast_bridge.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        storage_deposit(
            &aurora_fast_bridge.mock_token,
            aurora_fast_bridge.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;

        engine_mint_tokens(
            aurora_fast_bridge.user_aurora_address,
            &aurora_fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &aurora_fast_bridge.engine,
        )
        .await;

        aurora_fast_bridge.approve_spend_mock_tokens().await;

        let balance0 = aurora_fast_bridge.get_token_balance_on_aurora().await;

        aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                true,
                MAX_GAS,
                0,
            )
            .await;
        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );

        let balance1 = aurora_fast_bridge.get_token_balance_on_aurora().await;
        assert_eq!(balance1 + TRANSFER_TOKENS_AMOUNT, balance0);

        aurora_fast_bridge
            .withdraw_from_implicit_near_account(true)
            .await;
        let balance2 = aurora_fast_bridge.get_token_balance_on_aurora().await;
        assert_eq!(balance2, balance1);

        aurora_fast_bridge.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));

        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );

        aurora_fast_bridge.unlock_and_withdraw(1).await;

        let balance3 = aurora_fast_bridge.get_token_balance_on_aurora().await;
        assert_eq!(balance3, balance0);

        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn test_double_spend() {
        let aurora_fast_bridge = AuroraFastBridgeWrapper::init(false).await;
        mint_tokens_near(
            &aurora_fast_bridge.mock_token,
            TOKEN_SUPPLY,
            aurora_fast_bridge.engine.inner.id(),
        )
        .await;

        let second_aurora_fast_bridge =
            AuroraFastBridgeWrapper::init_second_user(&aurora_fast_bridge).await;

        aurora_fast_bridge
            .mint_wnear(TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;

        aurora_fast_bridge
            .engine
            .mint_wnear(
                &aurora_fast_bridge.wnear,
                aurora_fast_bridge.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await
            .unwrap();

        aurora_fast_bridge.approve_spend_wnear().await;
        aurora_fast_bridge.register_token(true).await.unwrap();
        aurora_fast_bridge.aurora_storage_deposit(true).await;

        storage_deposit(
            &aurora_fast_bridge.mock_token,
            aurora_fast_bridge.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        storage_deposit(
            &aurora_fast_bridge.mock_token,
            aurora_fast_bridge.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;

        engine_mint_tokens(
            aurora_fast_bridge.user_aurora_address,
            &aurora_fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &aurora_fast_bridge.engine,
        )
        .await;

        engine_mint_tokens(
            second_aurora_fast_bridge.user_aurora_address,
            &aurora_fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &aurora_fast_bridge.engine,
        )
        .await;

        aurora_fast_bridge.approve_spend_mock_tokens().await;
        second_aurora_fast_bridge.approve_spend_mock_tokens().await;

        assert_eq!(
            aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            second_aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );

        aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                true,
                MAX_GAS,
                0,
            )
            .await;
        second_aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                true,
                MAX_GAS,
                0,
            )
            .await;
        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            second_aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );

        assert_eq!(
            aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            0
        );
        assert_eq!(
            second_aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            0
        );

        aurora_fast_bridge.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));

        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            second_aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );

        aurora_fast_bridge.unlock_and_withdraw(1).await;
        second_aurora_fast_bridge.unlock_and_withdraw(2).await;

        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            second_aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );

        assert_eq!(
            aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            second_aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
    }

    #[tokio::test]
    async fn test_token_transfer_fail() {
        let aurora_fast_bridge = AuroraFastBridgeWrapper::init(false).await;
        mint_tokens_near(
            &aurora_fast_bridge.mock_token,
            TOKEN_SUPPLY,
            aurora_fast_bridge.engine.inner.id(),
        )
        .await;
        aurora_fast_bridge
            .mint_wnear(TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;

        aurora_fast_bridge
            .engine
            .mint_wnear(
                &aurora_fast_bridge.wnear,
                aurora_fast_bridge.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await
            .unwrap();

        aurora_fast_bridge.approve_spend_wnear().await;
        aurora_fast_bridge.register_token(true).await.unwrap();
        aurora_fast_bridge.aurora_storage_deposit(true).await;

        storage_deposit(
            &aurora_fast_bridge.mock_token,
            aurora_fast_bridge.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        engine_mint_tokens(
            aurora_fast_bridge.user_aurora_address,
            &aurora_fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &aurora_fast_bridge.engine,
        )
        .await;
        aurora_fast_bridge.approve_spend_mock_tokens().await;
        assert_eq!(
            aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                false,
                MAX_GAS,
                0,
            )
            .await;
        assert_eq!(
            aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            0
        );
        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            TRANSFER_TOKENS_AMOUNT
        );

        aurora_fast_bridge
            .withdraw_from_implicit_near_account(true)
            .await;
        assert_eq!(
            aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );

        aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                false,
                200_000_000_000_000,
                0,
            )
            .await;

        assert_eq!(
            aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn test_withdraw_without_fast_bridge_withdraw_on_near() {
        let fast_bridge = AuroraFastBridgeWrapper::init(false).await;
        let second_aurora_fast_bridge =
            AuroraFastBridgeWrapper::init_second_user(&fast_bridge).await;

        mint_tokens_near(
            &fast_bridge.mock_token,
            TOKEN_SUPPLY,
            fast_bridge.engine.inner.id(),
        )
        .await;

        fast_bridge
            .mint_wnear(TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;

        fast_bridge
            .engine
            .mint_wnear(
                &fast_bridge.wnear,
                fast_bridge.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await
            .unwrap();

        fast_bridge.approve_spend_wnear().await;
        fast_bridge.register_token(true).await.unwrap();
        fast_bridge.aurora_storage_deposit(true).await;

        storage_deposit(
            &fast_bridge.mock_token,
            fast_bridge.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        storage_deposit(
            &fast_bridge.mock_token,
            fast_bridge.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;

        engine_mint_tokens(
            fast_bridge.user_aurora_address,
            &fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &fast_bridge.engine,
        )
        .await;

        engine_mint_tokens(
            second_aurora_fast_bridge.user_aurora_address,
            &fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &fast_bridge.engine,
        )
        .await;

        fast_bridge.approve_spend_mock_tokens().await;
        second_aurora_fast_bridge.approve_spend_mock_tokens().await;

        fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                true,
                MAX_GAS,
                0,
            )
            .await;
        second_aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                true,
                MAX_GAS,
                0,
            )
            .await;

        fast_bridge.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));

        fast_bridge.unlock_and_withdraw(1).await;
        second_aurora_fast_bridge.unlock_and_withdraw(2).await;

        assert_eq!(
            fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            second_aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
    }

    #[tokio::test]
    async fn get_implicit_near_account_id_for_self_test() {
        let aurora_fast_bridge = AuroraFastBridgeWrapper::init(false).await;
        mint_tokens_near(
            &aurora_fast_bridge.mock_token,
            TOKEN_SUPPLY,
            aurora_fast_bridge.engine.inner.id(),
        )
        .await;
        aurora_fast_bridge
            .mint_wnear(TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;
        aurora_fast_bridge.approve_spend_wnear().await;

        let output = aurora_fast_bridge.register_token(true).await;
        aurora_fast_bridge.aurora_storage_deposit(true).await;

        assert!(aurora_fast_bridge
            .get_implicit_near_account_id_for_self()
            .await
            .unwrap()
            .contains(&output.receipt_outcomes()[1].executor_id.to_string()));
    }

    #[tokio::test]
    async fn whitelist_mode_test() {
        let aurora_fast_bridge = AuroraFastBridgeWrapper::init(true).await;
        let second_aurora_fast_bridge =
            AuroraFastBridgeWrapper::init_second_user(&aurora_fast_bridge).await;

        assert_eq!(
            aurora_fast_bridge
                .is_user_whitelisted(second_aurora_fast_bridge.user_aurora_address)
                .await,
            Some(false)
        );
        assert_eq!(
            aurora_fast_bridge
                .is_user_whitelisted(aurora_fast_bridge.user_aurora_address)
                .await,
            Some(true)
        );

        mint_tokens_near(
            &aurora_fast_bridge.mock_token,
            TOKEN_SUPPLY,
            aurora_fast_bridge.engine.inner.id(),
        )
        .await;

        aurora_fast_bridge
            .engine
            .mint_wnear(
                &aurora_fast_bridge.wnear,
                aurora_fast_bridge.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await
            .unwrap();

        storage_deposit(
            &aurora_fast_bridge.mock_token,
            aurora_fast_bridge.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        storage_deposit(
            &aurora_fast_bridge.mock_token,
            aurora_fast_bridge.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;

        aurora_fast_bridge
            .mint_wnear(TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;
        second_aurora_fast_bridge
            .mint_wnear(TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;

        aurora_fast_bridge.approve_spend_wnear().await;
        second_aurora_fast_bridge.approve_spend_wnear().await;

        aurora_fast_bridge.register_token(true).await.unwrap();
        second_aurora_fast_bridge.aurora_storage_deposit(true).await;

        engine_mint_tokens(
            aurora_fast_bridge.user_aurora_address,
            &aurora_fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &aurora_fast_bridge.engine,
        )
        .await;
        engine_mint_tokens(
            second_aurora_fast_bridge.user_aurora_address,
            &aurora_fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &aurora_fast_bridge.engine,
        )
        .await;

        aurora_fast_bridge.approve_spend_mock_tokens().await;
        second_aurora_fast_bridge.approve_spend_mock_tokens().await;

        second_aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                false,
                MAX_GAS,
                0,
            )
            .await;
        assert_eq!(
            second_aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );

        aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                true,
                MAX_GAS,
                0,
            )
            .await;
        assert_eq!(
            aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            0
        );

        aurora_fast_bridge.set_whitelist_mode(false).await;
        assert_eq!(
            aurora_fast_bridge
                .is_user_whitelisted(second_aurora_fast_bridge.user_aurora_address)
                .await,
            Some(true)
        );
        assert_eq!(
            aurora_fast_bridge
                .is_user_whitelisted(aurora_fast_bridge.user_aurora_address)
                .await,
            Some(true)
        );

        second_aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                true,
                MAX_GAS,
                0,
            )
            .await;
        assert_eq!(
            second_aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            0
        );

        aurora_fast_bridge.set_whitelist_mode(true).await;
        aurora_fast_bridge
            .set_whitelist_mode_for_user(
                vec![
                    aurora_fast_bridge.user_aurora_address,
                    second_aurora_fast_bridge.user_aurora_address,
                ],
                vec![false, true],
            )
            .await;

        assert_eq!(
            aurora_fast_bridge
                .is_user_whitelisted(second_aurora_fast_bridge.user_aurora_address)
                .await,
            Some(true)
        );
        assert_eq!(
            aurora_fast_bridge
                .is_user_whitelisted(aurora_fast_bridge.user_aurora_address)
                .await,
            Some(false)
        );

        engine_mint_tokens(
            aurora_fast_bridge.user_aurora_address,
            &aurora_fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &aurora_fast_bridge.engine,
        )
        .await;
        engine_mint_tokens(
            second_aurora_fast_bridge.user_aurora_address,
            &aurora_fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &aurora_fast_bridge.engine,
        )
        .await;

        second_aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                false,
                MAX_GAS,
                0,
            )
            .await;
        assert_eq!(
            second_aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            0
        );

        aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                true,
                MAX_GAS,
                0,
            )
            .await;
        assert_eq!(
            aurora_fast_bridge
                .get_token_balance_on_aurora()
                .await
                .as_u64(),
            TRANSFER_TOKENS_AMOUNT
        );
    }

    #[tokio::test]
    async fn withdraw_by_other_user() {
        let aurora_fast_bridge = AuroraFastBridgeWrapper::init(false).await;
        let second_aurora_fast_bridge =
            AuroraFastBridgeWrapper::init_second_user(&aurora_fast_bridge).await;

        mint_tokens_near(
            &aurora_fast_bridge.mock_token,
            TOKEN_SUPPLY,
            aurora_fast_bridge.engine.inner.id(),
        )
        .await;

        aurora_fast_bridge
            .mint_wnear(TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;
        aurora_fast_bridge
            .engine
            .mint_wnear(
                &aurora_fast_bridge.wnear,
                aurora_fast_bridge.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await
            .unwrap();

        aurora_fast_bridge.approve_spend_wnear().await;

        aurora_fast_bridge.register_token(true).await.unwrap();

        aurora_fast_bridge.aurora_storage_deposit(true).await;

        assert_eq!(
            aurora_fast_bridge.get_token_aurora_address().await.unwrap(),
            aurora_fast_bridge.aurora_mock_token.address.raw().0
        );

        storage_deposit(
            &aurora_fast_bridge.mock_token,
            aurora_fast_bridge.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        storage_deposit(
            &aurora_fast_bridge.mock_token,
            aurora_fast_bridge.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;

        engine_mint_tokens(
            aurora_fast_bridge.user_aurora_address,
            &aurora_fast_bridge.aurora_mock_token,
            TRANSFER_TOKENS_AMOUNT,
            &aurora_fast_bridge.engine,
        )
        .await;

        aurora_fast_bridge.approve_spend_mock_tokens().await;

        let balance0 = aurora_fast_bridge.get_token_balance_on_aurora().await;

        aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                true,
                MAX_GAS,
                0,
            )
            .await;
        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );

        let balance1 = aurora_fast_bridge.get_token_balance_on_aurora().await;
        assert_eq!(balance1 + TRANSFER_TOKENS_AMOUNT, balance0);

        aurora_fast_bridge.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));

        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );

        second_aurora_fast_bridge.unlock_and_withdraw(1).await;

        let balance3 = aurora_fast_bridge.get_token_balance_on_aurora().await;
        assert_eq!(balance3, balance0);

        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn test_transfer_ether() {
        let aurora_fast_bridge = AuroraFastBridgeWrapper::init_eth(false).await;

        aurora_fast_bridge
            .mint_wnear(TOKEN_STORAGE_DEPOSIT + NEAR_DEPOSIT)
            .await;

        aurora_fast_bridge
            .engine
            .mint_wnear(
                &aurora_fast_bridge.wnear,
                aurora_fast_bridge.aurora_fast_bridge_contract.address,
                WNEAR_FOR_TOKENS_TRANSFERS,
            )
            .await
            .unwrap();

        aurora_fast_bridge.approve_spend_wnear().await;

        aurora_fast_bridge.register_token(true).await.unwrap();

        aurora_fast_bridge.aurora_storage_deposit(true).await;

        assert_eq!(
            aurora_fast_bridge
                .is_storage_registered(aurora_fast_bridge.engine.inner.id().to_string())
                .await
                .unwrap(),
            true
        );

        storage_deposit(
            &aurora_fast_bridge.engine.inner,
            aurora_fast_bridge.engine.inner.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;
        storage_deposit(
            &aurora_fast_bridge.engine.inner,
            aurora_fast_bridge.near_fast_bridge.id(),
            TOKEN_STORAGE_DEPOSIT,
        )
        .await;

        aurora_fast_bridge
            .mint_aurora_ether(TRANSFER_TOKENS_AMOUNT)
            .await;

        let balance0 = aurora_fast_bridge.get_user_ether_balance().await;
        assert_eq!(balance0, TRANSFER_TOKENS_AMOUNT);

        aurora_fast_bridge
            .init_token_transfer(
                TRANSFER_TOKENS_AMOUNT as u128,
                0,
                get_default_valid_till(),
                true,
                MAX_GAS,
                TRANSFER_TOKENS_AMOUNT,
            )
            .await;

        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );

        let balance1 = aurora_fast_bridge.get_user_ether_balance().await;
        assert_eq!(balance1 + TRANSFER_TOKENS_AMOUNT, balance0);

        aurora_fast_bridge.increment_current_eth_block().await;
        sleep(Duration::from_secs(15));

        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );

        aurora_fast_bridge.unlock_and_withdraw(1).await;

        let balance3 = aurora_fast_bridge.get_user_ether_balance().await;
        assert_eq!(balance3, balance0);

        assert_eq!(
            aurora_fast_bridge
                .user_balance_in_fast_bridge_on_aurora()
                .await
                .unwrap(),
            0
        );
    }
}
