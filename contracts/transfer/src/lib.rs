use near_sdk::collections::{LookupMap, LookupSet};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{near_bindgen, AccountId, log, PromiseOrValue, serde_json};
use near_sdk::env::block_timestamp;
use near_sdk::json_types::U128;
use std::time::{SystemTime, UNIX_EPOCH};
use near_sdk::serde::{Deserialize, Serialize};

mod event;
mod transfer_data;

const LOCK_TIME_MIN: u64 = 3600;
const LOCK_TIME_MAX: u64 = 7200;

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct TransferData {
    token: String,
    amount: u128,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct TokenMsg {
    valid_till: u64,
    transfer: TransferData,
    fee: TransferData,
    recipient: String,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Transfer {
    locked_accounts: LookupMap<AccountId, String>,
    available_tokens: LookupSet<String>,
}

impl Default for Transfer {
    fn default() -> Self {
        Self {
            locked_accounts: LookupMap::new(b"s".to_vec()),
            available_tokens: LookupSet::new(b"s".to_vec()),
        }
    }
}

#[near_bindgen]
impl Transfer {
    pub fn ft_on_transfer(
        &mut self,
        account_id: AccountId,
        amount: u128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        if !self.is_metadata_correct(msg.clone()) {
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

        let token_msg: TokenMsg = serde_json::from_str(&msg)
            .expect("Some error with json structure.");
        if token_msg.valid_till < block_timestamp() {
            log!("Transfer valid time not correct.");
            is_correct = false;
        }

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards.");
        let current_timestamp = since_the_epoch.as_secs();

        let lock_period = token_msg.valid_till - current_timestamp;
        if lock_period > LOCK_TIME_MAX ||
            lock_period < LOCK_TIME_MIN {
            log!("Lock period does not fit the terms of the contract.");
            is_correct = false;
        }

        if !self.available_tokens.contains(&token_msg.transfer.token) {
            log!("This transfer token not available.");
            is_correct = false;
        }

        if !self.available_tokens.contains(&token_msg.fee.token) {
            log!("This fee token not available.");
            is_correct = false;
        }
        is_correct
    }

    pub fn add_available_token(
        &mut self,
        token: String,
    ) {
        self.available_tokens.insert(&token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::{testing_env, VMContext};
    use near_sdk::test_utils::VMContextBuilder;
    use std::convert::{TryFrom};

    fn get_context(is_view: bool) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(AccountId::try_from("alice_near".to_string()).unwrap())
            .signer_account_id(AccountId::try_from("bob_near".to_string()).unwrap())
            .predecessor_account_id(AccountId::try_from("carol_near".to_string()).unwrap())
            .block_index(101)
            .block_timestamp(0)
            .is_view(is_view)
            .build()
    }

    #[test]
    fn add_available_token_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = Transfer::default();
        let test_token: String = "AKSJDHF34JDHRYUIKKO83UNMNX3".to_string();
        contract.add_available_token(test_token.clone());
        assert!(contract.available_tokens.contains(&test_token));
    }

    #[test]
    fn is_metadata_correct_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = Transfer::default();
        let test_token: String = "AKSJDHF34JDHRYUIKKO83UNMNX1".to_string();
        let test_token2: String = "AKSJDHF34JDHRYUIKKO83UNMNX2".to_string();
        contract.add_available_token(test_token.clone());
        contract.add_available_token(test_token2.clone());
        assert!(contract.available_tokens.contains(&test_token));
        assert!(contract.available_tokens.contains(&test_token2));

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards.");
        // Time suits the conditions
        let current_timestamp = since_the_epoch.as_secs() + LOCK_TIME_MIN + 20;
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "AKSJDHF34JDHRYUIKKO83UNMNX1",
                "amount": 100
            },
            "fee": {
                "token": "AKSJDHF34JDHRYUIKKO83UNMNX2",
                "amount": 100
            },
            "recipient": "RESJDHF34JDHRYUIKKO83UNMNX2"
        }"#);
        assert!(contract.is_metadata_correct(String::from(msg)));
    }

    #[test]
    fn metadata_not_correct_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = Transfer::default();
        let test_token: String = "AKSJDHF34JDHRYUIKKO83UNMNX1".to_string();
        contract.add_available_token(test_token.clone());
        assert!(contract.available_tokens.contains(&test_token));

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards.");
        // Time not suits the conditions
        let current_timestamp = since_the_epoch.as_secs();
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "AKSJDHF34JDHRYUIKKO83UNMNX1",
                "amount": 100
            },
            "fee": {
                "token": "AKSJDHF34JDHRYUIKKO83UNMNX2",
                "amount": 100
            },
            "recipient": "RESJDHF34JDHRYUIKKO83UNMNX2"
        }"#);
        assert!(!contract.is_metadata_correct(String::from(msg)));
    }

    #[test]
    fn lock_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = Transfer::default();
        let test_token: String = "AKSJDHF34JDHRYUIKKO83UNMNX1".to_string();
        let test_token2: String = "AKSJDHF34JDHRYUIKKO83UNMNX2".to_string();
        contract.add_available_token(test_token.clone());
        contract.add_available_token(test_token2.clone());
        assert!(contract.available_tokens.contains(&test_token));
        assert!(contract.available_tokens.contains(&test_token2));

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards.");
        // Time suits the conditions
        let current_timestamp = since_the_epoch.as_secs() + LOCK_TIME_MIN + 20;
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "AKSJDHF34JDHRYUIKKO83UNMNX1",
                "amount": 100
            },
            "fee": {
                "token": "AKSJDHF34JDHRYUIKKO83UNMNX2",
                "amount": 100
            },
            "recipient": "RESJDHF34JDHRYUIKKO83UNMNX2"
        }"#);
        assert!(contract.is_metadata_correct(String::from(msg.clone())));
        contract.lock(AccountId::try_from("alice_near".to_string()).unwrap(), msg);
        assert!(contract.locked_accounts.contains_key(&AccountId::try_from("alice_near".to_string()).unwrap()));
    }

    #[test]
    fn account_not_locked_test() {
        let context = get_context(false);
        testing_env!(context);
        let contract = Transfer::default();
        assert!(!contract.locked_accounts.contains_key(&AccountId::try_from("alice_near".to_string()).unwrap()));
    }

    #[test]
    fn unlock_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = Transfer::default();
        let test_token: String = "AKSJDHF34JDHRYUIKKO83UNMNX1".to_string();
        let test_token2: String = "AKSJDHF34JDHRYUIKKO83UNMNX2".to_string();
        contract.add_available_token(test_token.clone());
        contract.add_available_token(test_token2.clone());
        assert!(contract.available_tokens.contains(&test_token));
        assert!(contract.available_tokens.contains(&test_token2));

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards.");
        // Time suits the conditions
        let current_timestamp = since_the_epoch.as_secs() + LOCK_TIME_MIN + 20;
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "AKSJDHF34JDHRYUIKKO83UNMNX1",
                "amount": 100
            },
            "fee": {
                "token": "AKSJDHF34JDHRYUIKKO83UNMNX2",
                "amount": 100
            },
            "recipient": "RESJDHF34JDHRYUIKKO83UNMNX2"
        }"#);
        assert!(contract.is_metadata_correct(String::from(msg.clone())));
        contract.lock(AccountId::try_from("alice_near".to_string()).unwrap(), msg);
        assert!(contract.locked_accounts.contains_key(&AccountId::try_from("alice_near".to_string()).unwrap()));
        contract.unlock(AccountId::try_from("alice_near".to_string()).unwrap());
        assert!(!contract.locked_accounts.contains_key(&AccountId::try_from("alice_near".to_string()).unwrap()));
    }
}
