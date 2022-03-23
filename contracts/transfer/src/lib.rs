use near_sdk::collections::{LookupMap, LookupSet};
use near_sdk::AccountId;
use near_sdk::env::block_timestamp;
use near_sdk::serde_json::json;
use near_sdk_sim::lazy_static_include::syn::Meta;

pub type Metadata = json;
const AVAILABLE_TOKEN_ADDRESS: LookupSet<String> = LookupSet!["FIRST_ADDRESS".to_string(), "SECOND_ADDRESS".to_string()];

pub struct Transfer {
    locked_accounts: LookupMap<AccountId, Metadata>,
}

#[near_bindgen]
impl Transfer {
    pub fn ft_on_transfer(&mut self, account_id: AccountId, metadata: Metadata) -> bool {
        let mut lock_success = true;
        if self.is_metadata_correct(account_id.clone(), metadata) {
            self.lock(account_id, metadata);
        } else {
            lock_success = false;
        }
        lock_success
    }

    pub fn lock(&mut self, account_id: AccountId, metadata: Metadata) {
        self.locked_accounts.insert(&account_id, metadata);
    }

    pub fn unlock(&mut self, account_id: AccountId) {
        self.locked_accounts.remove(&account_id);
    }


    pub fn is_metadata_correct(&mut self, account_id: AccountId, metadata: Metadata) -> bool {
        let is_correct: bool = true;
        if metadata["valid_till"] < block_timestamp() {
            panic!("Transfer valid time not correct.");
        }

        if !AVAILABLE_TOKEN_ADDRESS.contains(metadata["transfer"]["token"]) {
            panic!("This transfer token not available.")
        }

        if !AVAILABLE_TOKEN_ADDRESS.contains(metadata["fee"]["token"]) {
            panic!("This fee token not available.")
        }
        is_correct
    }
}

#[cfg(test)]
mod tests {}
