use near_sdk::collections::{LookupMap, LookupSet};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{near_bindgen, ext_contract, AccountId, PromiseOrValue, serde_json, env, is_promise_success};
use near_sdk::env::{block_timestamp, signer_account_id};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
use std::str;

mod utils;

const LOCK_TIME_MIN: u64 = 3600;
const LOCK_TIME_MAX: u64 = 7200;
pub const NO_DEPOSIT: u128 = 0;


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
trait NEP141Token {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: u128) -> PromiseOrValue<U128>;
}

#[ext_contract(ext_self)]
trait InternalTokenInterface {
    fn withdraw_callback(&mut self, token_id: AccountId, amount: u128) -> PromiseOrValue<U128>;
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct SpectreBridge {
    pending_transfers: LookupMap<String, (AccountId, TransferMessage)>,
    supported_tokens: LookupSet<AccountId>,
    user_balances: LookupMap<AccountId, LookupMap<AccountId, u128>>,
    nonce: u128,
}

impl Default for SpectreBridge {
    fn default() -> Self {
        Self {
            pending_transfers: LookupMap::new(b"a".to_vec()),
            supported_tokens: LookupSet::new(b"b".to_vec()),
            user_balances: LookupMap::new(b"c".to_vec()),
            nonce: 0,
        }
    }
}

#[near_bindgen]
impl SpectreBridge {
    pub fn ft_on_transfer(
        &mut self,
        token_id: AccountId,
        amount: u128,
    ) -> PromiseOrValue<U128> {
        if !self.supported_tokens.contains(&token_id) {
            panic!("Token: {} not supported.", token_id);
        }
        self.update_balance(token_id, amount)
    }

    pub fn lock(
        &mut self,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let transfer_message = self.is_metadata_correct(msg).unwrap();
        let user_token_balance = self.user_balances.get(&env::signer_account_id())
            .unwrap_or_else(|| panic!("Balance in {} for user {} not found", transfer_message.transfer.token, env::signer_account_id()));

        let token_transfer_balance = user_token_balance.get(&transfer_message.transfer.token)
            .unwrap_or_else(|| panic!("Balance for token transfer: {} not found", &transfer_message.transfer.token));
        if token_transfer_balance < transfer_message.transfer.amount {
            //TODO: place for emit event
            panic!("Not enough transfer token balance.");
        }

        let token_fee_balance = user_token_balance.get(&transfer_message.fee.token)
            .unwrap_or_else(|| panic!("Balance for token fee: {} not found", &transfer_message.transfer.token));
        if token_fee_balance < transfer_message.fee.amount {
            //TODO: place for emit event
            panic!("Not enough fee token balance.");
        }

        self.decrease_balance(&transfer_message.transfer.token, &transfer_message.transfer.amount);
        self.decrease_balance(&transfer_message.fee.token, &transfer_message.fee.amount);

        PromiseOrValue::Value(U128::from(self.store_transfers(transfer_message)))
    }

    pub fn unlock(
        &mut self,
        nonce: u128,
    ) {
        let transaction_id = utils::get_transaction_id(nonce);
        let transfer = self.pending_transfers.get(&transaction_id)
            .unwrap_or_else(|| panic!("Transaction with id: {} not found", &transaction_id.to_string()));
        let transfer_data = transfer.1;

        if transfer.0 != env::signer_account_id() {
            panic!("Signer: {} transaction not fount:", &env::signer_account_id());
        }

        if block_timestamp() < transfer_data.valid_till {
            panic!("Valid time is not correct.");
        }

        self.increase_balance(&transfer_data.transfer.token, &transfer_data.transfer.amount);
        self.increase_balance(&transfer_data.fee.token, &transfer_data.fee.amount);
        self.pending_transfers.remove(&transaction_id);

        //TODO: emit event
    }

    #[private]
    fn update_balance(
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
    fn decrease_balance(
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
    fn increase_balance(
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

        if !self.supported_tokens.contains(&transfer_message.transfer.token) {
            return Err("This transfer token not supported.");
        }

        if !self.supported_tokens.contains(&transfer_message.fee.token) {
            return Err("This fee token not supported.");
        }

        Ok(transfer_message)
    }

    #[private]
    #[allow(dead_code)]
    fn add_supported_token(
        &mut self,
        token: AccountId,
    ) {
        self.supported_tokens.insert(&token);
    }

    #[private]
    fn store_transfers(
        &mut self,
        transfer_message: TransferMessage,
    ) -> u128 {
        self.nonce += 1;
        let transaction_id = utils::get_transaction_id(self.nonce);
        let account_pending = (signer_account_id(), transfer_message);
        self.pending_transfers.insert(&transaction_id, &account_pending);
        self.nonce
    }

    pub fn withdraw(
        &mut self,
        token_id: AccountId,
        amount: u128,
    ) -> PromiseOrValue<U128> {

        if !self.supported_tokens.contains(&token_id){
            panic!("Token: {}  not supported", token_id );
        }

        let user_balance = self.user_balances.get(&env::signer_account_id())
            .unwrap_or_else(|| { panic!("{}", "User not have balance".to_string()) });

        let balance = user_balance.get(&token_id)
            .unwrap_or_else(|| panic!("User token: {} , balance is 0", &token_id));

        if balance < amount {
            panic!("Not enough token balance");
        }

        ext_token::ft_transfer(
            env::signer_account_id(),
            amount,
            env::current_account_id(),
            NO_DEPOSIT,
            utils::TGAS,
        ).then(ext_self::withdraw_callback(
            token_id,
            amount,
            env::current_account_id(),
            NO_DEPOSIT,
            utils::terra_gas(40))).into()
    }

    #[allow(dead_code)]
    pub fn withdraw_callback(
        &mut self,
        token_id: AccountId,
        amount: u128,
    ) -> PromiseOrValue<U128> {
        if !is_promise_success() {
           panic!("Error transfer");
        }

        self.decrease_balance(&token_id, &amount);
        PromiseOrValue::Value(U128::from(0))
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
            .block_timestamp(1649402222)
            .is_view(is_view)
            .build()
    }

    fn get_context_for_unlock(is_view: bool) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(AccountId::try_from("alice_near".to_string()).unwrap())
            .signer_account_id(AccountId::try_from("bob_near".to_string()).unwrap())
            .predecessor_account_id(AccountId::try_from("carol_near".to_string()).unwrap())
            .block_index(200)
            .block_timestamp(1649402222 + LOCK_TIME_MIN + 30)
            .is_view(is_view)
            .build()
    }

    #[test]
    fn add_supported_token_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        contract.add_supported_token(token.clone());
        assert!(contract.supported_tokens.contains(&token));
    }

    #[test]
    fn is_metadata_correct_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let token: AccountId = AccountId::try_from("alice_near".to_string()).unwrap();
        contract.add_supported_token(token.clone());
        assert!(contract.supported_tokens.contains(&token));

        let current_timestamp = block_timestamp() + LOCK_TIME_MIN + 20;
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "alice_near",
                "amount": 100
            },
            "fee": {
                "token": "alice_near",
                "amount": 100
            },
            "recipient": "bob_near"
        }"#);

        let transfer_message = contract.is_metadata_correct(msg).unwrap();

        let original = TransferMessage {
            valid_till: current_timestamp,
            transfer: TransferData {
                token: AccountId::try_from("alice_near".to_string()).unwrap(),
                amount: 100,
            },
            fee: TransferData {
                token: AccountId::try_from("alice_near".to_string()).unwrap(),
                amount: 100,
            },
            recipient: "bob_near".to_string(),
        };
        assert_eq!(serde_json::to_string(&original).unwrap(), serde_json::to_string(&transfer_message).unwrap());
    }

    #[test]
    fn metadata_not_correct_valid_time_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let token: AccountId = AccountId::try_from("alice_near".to_string()).unwrap();
        contract.add_supported_token(token.clone());
        assert!(contract.supported_tokens.contains(&token));

        let current_timestamp = block_timestamp() - 20;
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "alice_near",
                "amount": 100
            },
            "fee": {
                "token": "alice_near",
                "amount": 100
            },
            "recipient": "bob_near"
        }"#);
        let transfer_message = contract.is_metadata_correct(msg);
        let err: Result<TransferMessage, &'static str> = Err("Transfer valid time not correct.");
        assert_eq!(serde_json::to_string(&err).unwrap(), serde_json::to_string(&transfer_message).unwrap());
    }

    #[test]
    fn metadata_lock_period_not_correct_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let token: AccountId = AccountId::try_from("alice_near".to_string()).unwrap();
        contract.add_supported_token(token.clone());
        assert!(contract.supported_tokens.contains(&token));

        let current_timestamp = block_timestamp();
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "alice_near",
                "amount": 100
            },
            "fee": {
                "token": "alice_near",
                "amount": 100
            },
            "recipient": "bob_near"
        }"#);
        let transfer_message = contract.is_metadata_correct(msg);
        let err: Result<TransferMessage, &'static str> = Err("Lock period does not fit the terms of the contract.");
        assert_eq!(serde_json::to_string(&err).unwrap(), serde_json::to_string(&transfer_message).unwrap());
    }

    #[test]
    fn metadata_transfer_token_not_available_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let transfer_token: AccountId = AccountId::try_from("token1_near".to_string()).unwrap();
        let fee_token: AccountId = AccountId::try_from("token2_near".to_string()).unwrap();
        contract.add_supported_token(transfer_token.clone());
        contract.add_supported_token(fee_token.clone());
        assert!(contract.supported_tokens.contains(&transfer_token));
        assert!(contract.supported_tokens.contains(&fee_token));

        let current_timestamp = block_timestamp() + LOCK_TIME_MIN + 20;
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "token3_near",
                "amount": 100
            },
            "fee": {
                "token": "token4_near",
                "amount": 100
            },
            "recipient": "bob_near"
        }"#);
        let transfer_message = contract.is_metadata_correct(msg);
        let err: Result<TransferMessage, &'static str> = Err("This transfer token not supported.");
        assert_eq!(serde_json::to_string(&err).unwrap(), serde_json::to_string(&transfer_message).unwrap());
    }

    #[test]
    fn metadata_fee_token_not_available_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let transfer_token: AccountId = AccountId::try_from("token1_near".to_string()).unwrap();
        let fee_token: AccountId = AccountId::try_from("token2_near".to_string()).unwrap();
        contract.add_supported_token(transfer_token.clone());
        contract.add_supported_token(fee_token.clone());
        assert!(contract.supported_tokens.contains(&transfer_token));
        assert!(contract.supported_tokens.contains(&fee_token));

        let current_timestamp = block_timestamp() + LOCK_TIME_MIN + 20;
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "token1_near",
                "amount": 100
            },
            "fee": {
                "token": "token3_near",
                "amount": 100
            },
            "recipient": "bob_near"
        }"#);
        let transfer_message = contract.is_metadata_correct(msg);
        let err: Result<TransferMessage, &'static str> = Err("This fee token not supported.");
        assert_eq!(serde_json::to_string(&err).unwrap(), serde_json::to_string(&transfer_message).unwrap());
    }

    #[test]
    fn increase_balance_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        contract.add_supported_token(transfer_token.clone());
        assert!(contract.supported_tokens.contains(&transfer_token));

        let balance: u128 = 100;

        contract.ft_on_transfer(AccountId::try_from(transfer_token.to_string()).unwrap(), balance);
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(100, amount);
    }

    #[test]
    fn decrease_balance_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        contract.add_supported_token(transfer_token.clone());
        assert!(contract.supported_tokens.contains(&transfer_token));

        let balance: u128 = 100;

        contract.ft_on_transfer(transfer_token.clone(), balance);
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(100, amount);

        contract.decrease_balance(&transfer_token, &balance);
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(0, amount);
    }

    #[test]
    fn lock_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_token2: AccountId = AccountId::try_from("token2_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance: u128 = 100;

        contract.add_supported_token(transfer_token.clone());
        contract.add_supported_token(transfer_token2.clone());
        assert!(contract.supported_tokens.contains(&transfer_token));
        assert!(contract.supported_tokens.contains(&transfer_token2));

        contract.ft_on_transfer(transfer_token.clone(), balance);
        contract.ft_on_transfer(transfer_token2.clone(), balance);

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(100, transfer_token_amount);
        let transfer_token2_amount = user_balance.get(&transfer_token2).unwrap();
        assert_eq!(100, transfer_token2_amount);


        let current_timestamp = block_timestamp() + LOCK_TIME_MIN + 20;
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "token_near",
                "amount": 50
            },
            "fee": {
                "token": "token2_near",
                "amount": 50
            },
            "recipient": "bob_near"
        }"#);
        contract.lock(msg);

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(50, transfer_token_amount);
        let transfer_token2_amount = user_balance.get(&transfer_token2).unwrap();
        assert_eq!(50, transfer_token2_amount);
    }

    #[test]
    fn unlock_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_token2: AccountId = AccountId::try_from("token2_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance: u128 = 100;

        contract.add_supported_token(transfer_token.clone());
        contract.add_supported_token(transfer_token2.clone());
        assert!(contract.supported_tokens.contains(&transfer_token));
        assert!(contract.supported_tokens.contains(&transfer_token2));

        contract.ft_on_transfer(transfer_token.clone(), balance);
        contract.ft_on_transfer(transfer_token2.clone(), balance);

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(100, transfer_token_amount);
        let transfer_token2_amount = user_balance.get(&transfer_token2).unwrap();
        assert_eq!(100, transfer_token2_amount);


        let current_timestamp = block_timestamp() + LOCK_TIME_MIN + 20;
        let mut msg: String = r#"
        {
            "valid_till": "#.to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token": "token_near",
                "amount": 50
            },
            "fee": {
                "token": "token2_near",
                "amount": 50
            },
            "recipient": "bob_near"
        }"#);
        contract.lock(msg);

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(50, transfer_token_amount);
        let transfer_token2_amount = user_balance.get(&transfer_token2).unwrap();
        assert_eq!(50, transfer_token2_amount);

        let context = get_context_for_unlock(false);
        testing_env!(context);
        contract.unlock(1);
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(100, transfer_token_amount);
        let transfer_token2_amount = user_balance.get(&transfer_token2).unwrap();
        assert_eq!(100, transfer_token2_amount);
    }
}
