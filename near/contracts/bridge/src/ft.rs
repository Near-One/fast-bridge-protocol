use crate::*;

use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::{serde_json, AccountId};

#[near_bindgen]
impl FungibleTokenReceiver for SpectreBridge {
    #[pause]
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        require!(
            sender_id == env::signer_account_id(),
            "Sender is not the same as the signer"
        );

        let token_account_id = env::predecessor_account_id();
        self.check_whitelist_token_and_account(&token_account_id, &sender_id);

        if !msg.is_empty() {
            let transfer_message: TransferMessage = serde_json::from_str(&msg)
                .unwrap_or_else(|_| env::panic_str("Invalid json format of the `TransferMessage`"));

            let update_balance = UpdateBalance {
                sender_id: sender_id.clone(),
                token: token_account_id,
                amount,
            };

            return self
                .init_transfer_internal(transfer_message, sender_id, Some(update_balance))
                .then(
                    ext_self::ext(env::current_account_id())
                        .with_static_gas(utils::tera_gas(5))
                        .init_transfer_internal_callback(),
                )
                .into();
        } else {
            self.update_balance(sender_id.clone(), token_account_id.clone(), amount.0);
        }

        PromiseOrValue::Value(U128::from(0))
    }
}
