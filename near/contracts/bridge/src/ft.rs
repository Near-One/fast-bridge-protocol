use crate::*;

use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::AccountId;

#[near_bindgen]
impl FungibleTokenReceiver for SpectreBridge {
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        #[allow(unused_variables)] msg: String,
    ) -> PromiseOrValue<U128> {
        require!(sender_id == env::signer_account_id());

        require!(
            self.whitelisted_tokens.is_empty()
                || self.whitelisted_tokens.contains(&predecessor_account_id()),
            format!("Token: {} not supported.", predecessor_account_id())
        );

        self.update_balance(signer_account_id(), predecessor_account_id(), amount.0)
    }
}
