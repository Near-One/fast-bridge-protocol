use crate::*;

use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::{base64, AccountId};

#[near_bindgen]
impl FungibleTokenReceiver for FastBridge {
    /// Transfers tokens to the Fast Bridge contract and initiates a transfer to Ethereum if the `msg` parameter is not empty.
    ///
    /// This function is called when the smart contract receives tokens from a sender. If `msg` is not empty, the function decodes the `msg` parameter, which is a `TransferMessage` in borsh Base64 format, and uses it to initiate a token transfer to Ethereum. Otherwise, the function treats it as a deposit action, increases the balance of the sender, and emits a `FastBridgeDepositEvent`.
    ///
    /// Note that this function overrides a standard NEP-141 implementation of `ft_on_transfer()` so the arguments of the function are the same.
    ///
    /// # Arguments
    ///
    /// * `sender_id` - The account ID of the sender.
    /// * `amount` - The amount of tokens being transferred.
    /// * `msg` - The transfer message in borsh Base64 format.
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
