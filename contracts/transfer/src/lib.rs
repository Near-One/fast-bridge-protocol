use near_sdk::collections::{LookupMap, LookupSet};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{near_bindgen, ext_contract, AccountId, log, PromiseOrValue, serde_json, env, Gas};
use near_sdk::env::{block_timestamp, sha256, signer_account_id};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};

use std::str;


const LOCK_TIME_MIN: u64 = 3600;
const LOCK_TIME_MAX: u64 = 7200;
pub const NO_DEPOSIT: u128 = 0;
pub const TGAS: Gas = near_sdk::Gas::ONE_TERA;

#[near_bindgen]
#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TransferData {
    token: AccountId,
    amount: u128,
}

#[near_bindgen]
#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TransferMessage {
    valid_till: u64,
    transfer: TransferData,
    fee: TransferData,
    recipient: String,
}

#[ext_contract(ext_token)]
trait InternalToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: u128) -> PromiseOrValue<U128>;
}

#[ext_contract(ext_self)]
trait InternalTokenInterface {
    fn withdraw_amount_callback(&mut self, transfer_message: TransferMessage) -> PromiseOrValue<U128>;
    fn update_balance_callback(&mut self, transfer_message: TransferMessage) -> PromiseOrValue<U128>;
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Transfer {
    pending_transfers: LookupMap<String, LookupMap<AccountId, TransferMessage>>,
    available_tokens: LookupSet<String>,
    user_balances: LookupMap<AccountId, LookupMap<AccountId, u128>>,
    transactions: u64,
}

impl Default for Transfer {
    fn default() -> Self {
        Self {
            pending_transfers: LookupMap::new(b"a".to_vec()),
            available_tokens: LookupSet::new(b"b".to_vec()),
            user_balances: LookupMap::new(b"c".to_vec()),
            transactions: 0,
        }
    }
}

#[near_bindgen]
impl Transfer {
    pub fn ft_on_transfer(
        &mut self,
        token_id: AccountId,
        amount: u128,
    ) -> PromiseOrValue<U128> {
        if self.available_tokens.contains(&token_id.to_string()) {
            return self.update_balance(token_id, amount);
        }
        PromiseOrValue::Value(U128::from(amount))
    }

    pub fn lock(
        &mut self,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let transfer_message: TransferMessage;
        match self.is_metadata_correct(msg) {
            Ok(tm) => { transfer_message = tm }
            Err(err) => {
                log!("Metadata not correct: {}", err);
                return PromiseOrValue::Value(U128::from(0));
            }
        }

        let user_token_balance = self.user_balances.get(&env::signer_account_id()).unwrap();
        if let Some(token_tr_balance) = user_token_balance.get(&transfer_message.transfer.token) {
            if token_tr_balance < transfer_message.transfer.amount {
                log!("Not enough transfer token balance.");
                //TODO: place for emit event
                return PromiseOrValue::Value(U128::from(0));
            }
        }

        if let Some(token_fee_balance) = user_token_balance.get(&transfer_message.fee.token) {
            if token_fee_balance < transfer_message.fee.amount {
                log!("Not enough fee token balance.");
                //TODO: place for emit event
                return PromiseOrValue::Value(U128::from(0));
            }
        }

        self.substract_balance(&transfer_message.transfer.token, &transfer_message.transfer.amount);
        self.substract_balance(&transfer_message.fee.token, &transfer_message.fee.amount);

        PromiseOrValue::Value(U128::from(self.store_transfers(transfer_message) as u128))
    }

    pub fn unlock(
        &mut self,
        nonce: u64,
    ) -> PromiseOrValue<U128> {
        let sh = sha256(&nonce.to_string().as_bytes());
        let transaction_id = str::from_utf8(&sh).unwrap();
        if let Some(transfer) = self.pending_transfers.get(&transaction_id.to_string().clone()) {
            if let Some(transfer_data) = transfer.get(&signer_account_id()) {
                if block_timestamp() < transfer_data.valid_till {
                    self.increase_balance(&transfer_data.transfer.token, &transfer_data.transfer.amount);
                    self.increase_balance(&transfer_data.fee.token, &transfer_data.fee.amount);

                    self.pending_transfers.remove(&transaction_id.to_string());

                    self.withdraw(transfer_data)
                } else {
                    panic!("Valid time is not correct.");
                }
            } else {
                panic!("Signer not same.");
            }
        } else {
            panic!("Transaction id not correct");
        }
    }

    #[private]
    pub fn update_balance(
        &mut self,
        token_id: AccountId,
        amount: u128,
    ) -> PromiseOrValue<U128> {
        if let Some(mut user_balances) = self.user_balances.get(&signer_account_id()) {
            if let Some(mut token_amount) = user_balances.get(&token_id) {
                token_amount += amount;
                user_balances.insert(&token_id, &token_amount);
            } else {
                user_balances.insert(&token_id, &amount);
            }
            self.user_balances.insert(&signer_account_id(), &user_balances);
        } else {
            let mut token_balance = LookupMap::new(b"tb".to_vec());
            token_balance.insert(&token_id, &amount);
            self.user_balances.insert(&signer_account_id(), &token_balance);
        }
        PromiseOrValue::Value(U128::from(0))
    }

    #[private]
    pub fn substract_balance(
        &mut self,
        token_id: &AccountId,
        amount: &u128,
    ) {
        let mut user_token_balance = self.user_balances.get(&env::signer_account_id()).unwrap();
        let balance = user_token_balance.get(token_id).unwrap() - amount;
        user_token_balance.insert(token_id, &balance);
        self.user_balances.insert(&env::signer_account_id(), &user_token_balance);
    }


    #[private]
    pub fn increase_balance(
        &mut self,
        token_id: &AccountId,
        amount: &u128,
    ) {
        let mut user_token_balance = self.user_balances.get(&env::signer_account_id()).unwrap();
        let balance = user_token_balance.get(token_id).unwrap() + amount;
        user_token_balance.insert(token_id, &balance);
        self.user_balances.insert(&env::signer_account_id(), &user_token_balance);
    }

    #[private]
    pub fn is_metadata_correct(
        &mut self,
        msg: String,
    ) -> Result<TransferMessage, &'static str> {
        let transfer_message: TransferMessage = serde_json::from_str(&msg)
            .expect("Some error with json structure.");
        if transfer_message.valid_till < block_timestamp() {
            return Err("Transfer valid time not correct.");
        }

        let lock_period = transfer_message.valid_till - block_timestamp();
        if !(LOCK_TIME_MIN..=LOCK_TIME_MAX).contains(&lock_period) {
            return Err("Lock period does not fit the terms of the contract.");
        }

        if !self.available_tokens.contains(&transfer_message.transfer.token.to_string()) {
            return Err("This transfer token not available.");
        }

        if !self.available_tokens.contains(&transfer_message.fee.token.to_string()) {
            return Err("This fee token not available.");
        }

        Ok(transfer_message)
    }

    #[private]
    pub fn add_available_token(
        &mut self,
        token: String,
    ) {
        self.available_tokens.insert(&token);
    }

    #[private]
    pub fn store_transfers(
        &mut self,
        transfer_message: TransferMessage,
    ) -> u64 {
        self.transactions += 1;
        let transaction_id = "asd";
        //str::from_utf8(&sha256(&self.transactions.to_string().as_bytes())).unwrap();
        let mut account_pending = LookupMap::new(b"pt".to_vec());
        account_pending.insert(&signer_account_id(), &transfer_message);
        self.pending_transfers.insert(&transaction_id.to_string(), &account_pending);
        self.transactions
    }

    #[private]
    pub fn withdraw(
        &mut self,
        transfer_message: TransferMessage,
    ) -> PromiseOrValue<U128> {
        ext_token::ft_transfer(
            env::signer_account_id(),
            transfer_message.transfer.amount,
            env::current_account_id(),
            NO_DEPOSIT,
            TGAS,
        ).then(ext_self::withdraw_amount_callback(
            transfer_message,
            env::current_account_id(),
            NO_DEPOSIT,
            self.terra_gas(40))).into()
    }

    #[allow(dead_code)]
    pub fn withdraw_amount_callback(
        &mut self,
        transfer_message: TransferMessage,
    ) -> PromiseOrValue<U128> {
        assert_eq!(
            env::promise_results_count(),
            1,
            "Withdraw amount callback."
        );

        ext_token::ft_transfer(
            env::signer_account_id(),
            transfer_message.fee.amount,
            env::current_account_id(),
            NO_DEPOSIT,
            self.terra_gas(5),
        ).then(ext_self::update_balance_callback(
            transfer_message,
            env::current_account_id(),
            NO_DEPOSIT,
            self.terra_gas(5),
        )).into()
    }

    #[allow(dead_code)]
    pub fn update_balance_callback(
        &mut self,
        transfer_message: TransferMessage,
    ) -> PromiseOrValue<U128> {
        assert_eq!(
            env::promise_results_count(),
            1,
            "Update balance callback method."
        );

        self.substract_balance(&transfer_message.transfer.token, &transfer_message.transfer.amount);
        self.substract_balance(&transfer_message.fee.token, &transfer_message.fee.amount);

        //TODO: emit event
        PromiseOrValue::Value(U128::from(0))
    }

    #[private]
    pub fn terra_gas(&self, gas: u64) -> Gas {
        TGAS * gas
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

    /*#[test]
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

        let current_timestamp = block_timestamp() + LOCK_TIME_MIN + 20;
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

        let current_timestamp = block_timestamp();
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


        let current_timestamp = block_timestamp() + LOCK_TIME_MIN + 20;
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
        contract.lock(AccountId::try_from("alice_near".to_string()).unwrap(), 200, msg);
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


        // Time suits the conditions
        let current_timestamp = block_timestamp() + LOCK_TIME_MIN + 20;
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
        contract.lock(AccountId::try_from("alice_near".to_string()).unwrap(), 200, msg);
        assert!(contract.locked_accounts.contains_key(&AccountId::try_from("alice_near".to_string()).unwrap()));
        contract.unlock(AccountId::try_from("alice_near".to_string()).unwrap());
        assert!(!contract.locked_accounts.contains_key(&AccountId::try_from("alice_near".to_string()).unwrap()));
    }*/
}
