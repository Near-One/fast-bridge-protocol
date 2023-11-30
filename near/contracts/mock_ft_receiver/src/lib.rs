use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::require;
use near_sdk::{near_bindgen, AccountId, PanicOnDefault, PromiseOrValue};

#[near_bindgen]
#[derive(BorshSerialize, BorshDeserialize, PanicOnDefault)]
pub struct Contract {
    refund_amount: Option<U128>,
    expected_msg: Option<String>,
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(refund_amount: Option<U128>, expected_msg: Option<String>) -> Self {
        Self {
            refund_amount,
            expected_msg,
        }
    }

    pub fn set_config(&mut self, refund_amount: Option<U128>, expected_msg: Option<String>) {
        self.refund_amount = refund_amount;
        self.expected_msg = expected_msg;
    }
}

#[near_bindgen]
impl FungibleTokenReceiver for Contract {
    fn ft_on_transfer(
        &mut self,
        #[allow(unused_variables)] sender_id: AccountId,
        #[allow(unused_variables)] amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        if let Some(expected_msg) = &self.expected_msg {
            require!(expected_msg == &msg, "ft_on_transfer unexpected msg");
        }

        PromiseOrValue::Value(self.refund_amount.unwrap_or(U128(0)))
    }
}
