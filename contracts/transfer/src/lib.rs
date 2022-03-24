use near_sdk::collections::{LookupMap, LookupSet};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{near_bindgen, AccountId, log, PromiseOrValue, serde_json};
use near_sdk::env::block_timestamp;
use near_sdk::json_types::U128;
use std::time::{SystemTime, UNIX_EPOCH};
use near_sdk::serde_json::from_str;

const LOCK_TIME_MIN: u64 = 3600;
const LOCK_TIME_MAX: u64 = 7200;
const AVAILABLE_TOKEN_ADDRESS: LookupSet<String> = ["FIRST_ADDRESS".to_string(), "SECOND_ADDRESS".to_string()];

pub struct TransferData {
    token: String,
    amount: u128,
}

#[derive(Deserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, Serialize))]
#[serde(crate = "near_sdk::serde")]
pub struct TokenMsg {
    valid_till: u64,
    transfer: TransferData,
    fee: TransferData,
    recipient: String,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Transfer {
    locked_accounts: LookupMap<AccountId, String>,
}

#[near_bindgen]
impl Transfer {
    pub fn ft_on_transfer(
        &mut self,
        account_id: AccountId,
        amount: u128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        if !self.is_metadata_correct( msg.clone()) {
            log!("Something wrong with message, metadata not correct.");
            PromiseOrValue::Value(0);
        }
        self.lock(account_id, msg);
        PromiseOrValue::Value(U128::from(amount))
    }

    pub fn lock(
        &mut self,
        account_id: AccountId,
        msg: String,
    ) {
        self.locked_accounts.insert(&account_id, &msg);
    }

    pub fn unlock(
        &mut self,
        account_id:
        AccountId,
    ) {
        self.locked_accounts.remove(&account_id);
    }


    pub fn is_metadata_correct(
        &mut self,
        msg: String,
    ) -> bool {
        let mut is_correct: bool = true;
        if msg.is_empty() {
            panic!("Token message is empty.");
        }

        let token_msg: TokenMsg = serde_json::from_str(&msg).expect("Can't parse TokenMsg");
        if token_msg.valid_till < block_timestamp() {
            log!("Transfer valid time not correct.");
            is_correct = false;
        }

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards.");
        let current_timestamp = u64::from(since_the_epoch.as_millis());
        let lock_period = token_msg.valid_till - current_timestamp;
        if lock_period > LOCK_TIME_MAX ||
            lock_period < LOCK_TIME_MIN {
            log!("Lock period does not fit the terms of the contract.");
            is_correct = false;
        }

        if !AVAILABLE_TOKEN_ADDRESS.contains(&token_msg.transfer.token) {
            log!("This transfer token not available.");
            is_correct = false;
        }

        if !AVAILABLE_TOKEN_ADDRESS.contains(&token_msg.fee.token) {
            log!("This fee token not available.");
            is_correct = false;
        }
        is_correct
    }
}

#[cfg(test)]
mod tests {}
