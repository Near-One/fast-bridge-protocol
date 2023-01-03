use crate::*;

use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::{serde_json, AccountId};

#[near_bindgen]
impl FungibleTokenReceiver for SpectreBridge {
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
        self.update_balance(sender_id.clone(), token_account_id, amount.0);

        if !msg.is_empty() {
            let transfer_message: TransferMessage = serde_json::from_str(&msg)
                .unwrap_or_else(|_| env::panic_str("Invalid json format of the `TransferMessage`"));
            self.init_transfer_internal(transfer_message, sender_id);
        }

        PromiseOrValue::Value(U128::from(0))
    }
}
