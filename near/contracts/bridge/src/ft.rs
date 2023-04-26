use crate::*;

use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::{base64, AccountId};

#[near_bindgen]
impl FungibleTokenReceiver for FastBridge {
    /// Transfer tokens to the Fast Bridge contract and
    /// if the msg not empty initiate tokens transfer to Ethereum
    /// msg if present is the TransferMessage in borsh Base64 format
    #[pause]
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let token_account_id = env::predecessor_account_id();
        self.check_whitelist_token_and_account(&token_account_id, &sender_id);

        if !msg.is_empty() {
            let decoded_base64 =
                base64::decode(&msg).unwrap_or_else(|_| env::panic_str("Invalid base64 message"));
            let transfer_message =
                TransferMessage::try_from_slice(&decoded_base64).unwrap_or_else(|_| {
                    env::panic_str("Invalid borsh format of the `TransferMessage`")
                });

            let update_balance = UpdateBalance {
                sender_id: sender_id.clone(),
                token: token_account_id,
                amount,
            };

            self.init_transfer_internal(transfer_message, sender_id, Some(update_balance))
                .into()
        } else {
            self.increase_balance(&sender_id, &token_account_id, &amount.0);

            Event::FastBridgeDepositEvent {
                sender_id,
                token: token_account_id,
                amount,
            }
            .emit();
            PromiseOrValue::Value(U128::from(0))
        }
    }
}
