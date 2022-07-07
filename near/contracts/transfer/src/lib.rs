use crate::lp_relayer::TransferProof;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedSet};
use near_sdk::env::{
    block_timestamp, current_account_id, predecessor_account_id, signer_account_id,
};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use near_sdk::Promise;
use near_sdk::{
    env, ext_contract, is_promise_success, near_bindgen, require, serde_json, AccountId, Duration,
    PromiseOrValue, PromiseResult,
};
use parse_duration::parse;
use spectre_bridge_common::*;
use std::str;

pub use crate::ft::*;

mod ft;
mod lp_relayer;
mod utils;

pub const NO_DEPOSIT: u128 = 0;

#[ext_contract(ext_prover)]
pub trait Prover {
    #[result_serializer(borsh)]
    fn verify_log_entry(
        &self,
        #[serializer(borsh)] log_index: u64,
        #[serializer(borsh)] log_entry_data: Vec<u8>,
        #[serializer(borsh)] receipt_index: u64,
        #[serializer(borsh)] receipt_data: Vec<u8>,
        #[serializer(borsh)] header_data: Vec<u8>,
        #[serializer(borsh)] proof: Vec<Vec<u8>>,
        #[serializer(borsh)] skip_bridge_call: bool,
    ) -> bool;
}

#[ext_contract(ext_token)]
trait NEP141Token {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[ext_contract(ext_self)]
trait SpectreBridgeInterface {
    fn withdraw_callback(&mut self, token_id: AccountId, amount: U128);
    fn verify_log_entry_callback(&mut self, proof: TransferProof) -> Promise;
}

#[near_bindgen]
#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct TransferData {
    token: AccountId,
    amount: u128,
}

#[near_bindgen]
#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct TransferMessage {
    chain_id: u32,
    valid_till: u64,
    transfer: TransferDataEthereum,
    fee: TransferDataNear,
    recipient: EthAddress,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct SpectreBridge {
    pending_transfers: LookupMap<String, (AccountId, TransferMessage)>,
    user_balances: LookupMap<AccountId, LookupMap<AccountId, u128>>,
    nonce: u128,
    proover_accounts: LookupMap<u32, AccountId>,
    current_chain_id: u32,
    eth_bridge_contract: EthAddress,
    lock_time_min: Duration,
    lock_time_max: Duration,
    whitelisted_tokens: UnorderedSet<AccountId>,
}

impl Default for SpectreBridge {
    fn default() -> Self {
        Self {
            pending_transfers: LookupMap::new(b"a".to_vec()),
            user_balances: LookupMap::new(b"c".to_vec()),
            nonce: 0,
            current_chain_id: 4,
            proover_accounts: LookupMap::new(b"pr_ct".to_vec()),
            eth_bridge_contract: [0u8; 20],
            lock_time_min: parse("1h").unwrap().as_nanos() as u64,
            lock_time_max: parse("24h").unwrap().as_nanos() as u64,
            whitelisted_tokens: UnorderedSet::new(b"b".to_vec()),
        }
    }
}

#[near_bindgen]
impl SpectreBridge {
    #[init]
    pub fn new(
        eth_bridge_contract: EthAddress,
        lock_time_min: String,
        lock_time_max: String,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");

        Self {
            pending_transfers: LookupMap::new(b"a".to_vec()),
            user_balances: LookupMap::new(b"a".to_vec()),
            nonce: 0,
            proover_accounts: LookupMap::new(b"a".to_vec()),
            current_chain_id: 4,
            eth_bridge_contract,
            lock_time_min: parse(lock_time_min.as_str()).unwrap().as_nanos() as u64,
            lock_time_max: parse(lock_time_max.as_str()).unwrap().as_nanos() as u64,
            whitelisted_tokens: UnorderedSet::new(b"b".to_vec()),
        }
    }

    pub fn lock(&mut self, msg: String) -> PromiseOrValue<U128> {
        let transfer_message = self.is_metadata_correct(msg);
        let user_token_balance = self
            .user_balances
            .get(&env::signer_account_id())
            .unwrap_or_else(|| {
                panic!(
                    "Balance in {} for user {} not found",
                    transfer_message.transfer.token_near,
                    env::signer_account_id()
                )
            });

        let token_transfer_balance = user_token_balance
            .get(&transfer_message.transfer.token_near)
            .unwrap_or_else(|| {
                panic!(
                    "Balance for token transfer: {} not found",
                    &transfer_message.transfer.token_near
                )
            });

        require!(
            token_transfer_balance > u128::from(transfer_message.transfer.amount),
            "Not enough transfer token balance."
        );

        let token_fee_balance = user_token_balance
            .get(&transfer_message.fee.token)
            .unwrap_or_else(|| {
                panic!(
                    "Balance for token fee: {} not found",
                    &transfer_message.transfer.token_near
                )
            });
        require!(
            token_fee_balance > u128::from(transfer_message.fee.amount),
            "Not enough fee token balance."
        );

        self.decrease_balance(
            &transfer_message.transfer.token_near,
            &u128::from(transfer_message.transfer.amount),
        );

        self.decrease_balance(
            &transfer_message.fee.token,
            &u128::from(transfer_message.fee.amount),
        );

        let nonce = U128::from(self.store_transfers(transfer_message.clone()));

        Event::SpectreBridgeTransferEvent {
            nonce,
            chain_id: transfer_message.chain_id,
            valid_till: transfer_message.valid_till,
            transfer: TransferDataEthereum {
                token_near: transfer_message.transfer.token_near,
                token_eth: transfer_message.transfer.token_eth,
                amount: transfer_message.transfer.amount,
            },
            fee: TransferDataNear {
                token: transfer_message.fee.token,
                amount: transfer_message.fee.amount,
            },
            recipient: transfer_message.recipient,
        }
        .emit();

        PromiseOrValue::Value(nonce)
    }

    pub fn unlock(&mut self, nonce: u128) {
        let transaction_id = utils::get_transaction_id(nonce);
        let transfer = self
            .pending_transfers
            .get(&transaction_id)
            .unwrap_or_else(|| {
                panic!(
                    "Transaction with id: {} not found",
                    &transaction_id.to_string()
                )
            });
        let transfer_data = transfer.1;

        require!(
            transfer.0 == env::signer_account_id(),
            format!(
                "Signer: {} transaction not fount:",
                &env::signer_account_id()
            )
        );
        require!(
            block_timestamp() > transfer_data.valid_till,
            "Valid time is not correct."
        );

        self.increase_balance(
            &transfer_data.transfer.token_near,
            &u128::from(transfer_data.transfer.amount),
        );
        self.increase_balance(
            &transfer_data.fee.token,
            &u128::from(transfer_data.fee.amount),
        );
        self.pending_transfers.remove(&transaction_id);

        Event::SpectreBridgeUnlockEvent {
            nonce: U128(nonce),
            account: signer_account_id(),
        }
        .emit();
    }

    pub fn lp_unlock(&mut self, proof: Proof) {
        let parsed_proof = lp_relayer::TransferProof::parse(proof.clone());

        let proover_account = self
            .proover_accounts
            .get(&self.current_chain_id)
            .unwrap_or_else(|| {
                panic!(
                    "Proover account for current chain id:{}",
                    self.current_chain_id
                )
            });

        ext_prover::ext(proover_account)
            .with_static_gas(utils::terra_gas(50))
            .with_attached_deposit(utils::NO_DEPOSIT)
            .verify_log_entry(
                proof.log_index,
                proof.log_entry_data,
                proof.receipt_index,
                proof.receipt_data,
                proof.header_data,
                proof.proof,
                false,
            )
            .then(
                ext_self::ext(current_account_id())
                    .with_static_gas(utils::terra_gas(50))
                    .with_attached_deposit(utils::NO_DEPOSIT)
                    .verify_log_entry_callback(parsed_proof),
            );
    }

    #[private]
    pub fn verify_log_entry_callback(&mut self, proof: TransferProof) {
        let verification_result = match env::promise_result(0) {
            PromiseResult::NotReady => 0,
            PromiseResult::Failed => 0,
            PromiseResult::Successful(result) => result[0],
        };

        if verification_result == 0 {
            panic!("Failed to verify the proof");
        }

        let transaction_id = utils::get_transaction_id(proof.nonce);

        let transfer = self
            .pending_transfers
            .get(&transaction_id)
            .unwrap_or_else(|| {
                panic!(
                    "Transaction with id: {} not found",
                    &transaction_id.to_string()
                )
            });
        let transfer_data = transfer.1;

        require!(
            proof.recipient == transfer_data.recipient,
            format!(
                "Wrong recipient {:?}, expected {:?}",
                proof.recipient, transfer_data.recipient
            )
        );

        require!(
            proof.token == transfer_data.transfer.token_eth,
            format!(
                "Wrong token transferred {:?}, expected {:?}",
                proof.token, transfer_data.transfer.token_eth
            )
        );

        require!(
            proof.amount == transfer_data.transfer.amount.0,
            format!(
                "Wrong amount transferred {}, expected {}",
                proof.amount, transfer_data.transfer.amount.0
            )
        );

        self.increase_balance(
            &transfer_data.transfer.token_near,
            &u128::from(transfer_data.transfer.amount),
        );
        self.increase_balance(
            &transfer_data.fee.token,
            &u128::from(transfer_data.fee.amount),
        );
        self.pending_transfers.remove(&transaction_id);

        Event::SpectreBridgeUnlockEvent {
            nonce: U128(proof.nonce),
            account: signer_account_id(),
        }
        .emit();
    }

    #[private]
    fn update_balance(
        &mut self,
        account_id: AccountId,
        token_id: AccountId,
        amount: u128,
    ) -> PromiseOrValue<U128> {
        if let Some(mut user_balances) = self.user_balances.get(&account_id) {
            if let Some(mut token_amount) = user_balances.get(&token_id) {
                token_amount += amount;
                user_balances.insert(&token_id, &token_amount);
            } else {
                user_balances.insert(&token_id, &amount);
            }
            self.user_balances.insert(&account_id, &user_balances);
        } else {
            let mut token_balance = LookupMap::new(b"tb".to_vec());
            token_balance.insert(&token_id, &amount);
            self.user_balances.insert(&account_id, &token_balance);
        }
        Event::SpectreBridgeDepositEvent {
            account: account_id,
            token: token_id,
            amount: U128(amount),
        }
        .emit();
        PromiseOrValue::Value(U128::from(0))
    }

    #[private]
    fn decrease_balance(&mut self, token_id: &AccountId, amount: &u128) {
        let mut user_token_balance = self.user_balances.get(&env::signer_account_id()).unwrap();
        let balance = user_token_balance.get(token_id).unwrap() - amount;
        user_token_balance.insert(token_id, &balance);
        self.user_balances
            .insert(&env::signer_account_id(), &user_token_balance);
    }

    #[private]
    fn increase_balance(&mut self, token_id: &AccountId, amount: &u128) {
        let mut user_token_balance = self.user_balances.get(&env::signer_account_id()).unwrap();
        let balance = user_token_balance.get(token_id).unwrap() + amount;
        user_token_balance.insert(token_id, &balance);
        self.user_balances
            .insert(&env::signer_account_id(), &user_token_balance);
    }

    #[private]
    pub fn is_metadata_correct(&mut self, msg: String) -> TransferMessage {
        let transfer_message: TransferMessage =
            serde_json::from_str(&msg).expect("Some error with json structure.");

        require!(
            transfer_message.valid_till > block_timestamp(),
            format!(
                "Transfer valid time:{} not correct, block timestamp:{}.",
                transfer_message.valid_till,
                block_timestamp()
            )
        );

        let lock_period = transfer_message.valid_till - block_timestamp();
        require!(
            (self.lock_time_min..=self.lock_time_max).contains(&lock_period),
            format!(
                "Lock period:{} does not fit the terms of the contract.",
                lock_period
            )
        );
        require!(
            self.whitelisted_tokens.is_empty()
                || self
                    .whitelisted_tokens
                    .contains(&transfer_message.transfer.token_near),
            "This transfer token not supported."
        );
        require!(
            self.whitelisted_tokens.is_empty()
                || self
                    .whitelisted_tokens
                    .contains(&transfer_message.fee.token),
            "This fee token not supported."
        );

        transfer_message
    }

    #[private]
    fn store_transfers(&mut self, transfer_message: TransferMessage) -> u128 {
        self.nonce += 1;
        let transaction_id = utils::get_transaction_id(self.nonce);
        let account_pending = (signer_account_id(), transfer_message);
        self.pending_transfers
            .insert(&transaction_id, &account_pending);
        self.nonce
    }

    #[payable]
    pub fn withdraw(&mut self, token_id: AccountId, amount: U128) {
        let user_balance = self
            .user_balances
            .get(&env::signer_account_id())
            .unwrap_or_else(|| panic!("{}", "User not have balance".to_string()));

        let balance = user_balance
            .get(&token_id)
            .unwrap_or_else(|| panic!("User token: {} , balance is 0", &token_id.clone()));

        require!(
            balance >= u128::try_from(amount).unwrap(),
            "Not enough token balance"
        );

        ext_token::ext(token_id.clone())
            .with_static_gas(utils::terra_gas(5))
            .with_attached_deposit(1)
            .ft_transfer(
                signer_account_id(),
                amount,
                Some(format!(
                    "Withdraw from: {} amount: {}",
                    current_account_id(),
                    u128::try_from(amount).unwrap()
                )),
            )
            .then(
                ext_self::ext(current_account_id())
                    .with_static_gas(utils::terra_gas(2))
                    .with_attached_deposit(utils::NO_DEPOSIT)
                    .withdraw_callback(token_id, amount),
            );
    }

    #[private]
    pub fn withdraw_callback(&mut self, token_id: AccountId, amount: U128) {
        require!(is_promise_success(), "Error transfer");

        self.decrease_balance(&token_id, &u128::try_from(amount).unwrap());
    }

    #[private]
    pub fn add_proover_contract(&mut self, chain_id: u32, proover_account: AccountId) {
        self.proover_accounts.insert(&chain_id, &proover_account);
    }

    #[private]
    pub fn set_enear_address(&mut self, near_address: String) {
        require!(
            utils::is_valid_eth_address(near_address.clone()),
            format!("Ethereum address:{} not valid.", near_address)
        );
        self.eth_bridge_contract = utils::get_eth_address(near_address);
    }

    #[private]
    pub fn set_lock_time(&mut self, lock_time_min: String, lock_time_max: String) {
        self.lock_time_min = parse(lock_time_min.as_str()).unwrap().as_nanos() as u64;
        self.lock_time_max = parse(lock_time_max.as_str()).unwrap().as_nanos() as u64;
    }

    #[private]
    pub fn add_supported_token(&mut self, token: AccountId) {
        self.whitelisted_tokens.insert(&token);
    }

    #[private]
    pub fn set_current_chain_id(&mut self, chain_id: u32) {
        self.current_chain_id = chain_id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, VMContext};
    use std::convert::TryFrom;

    fn get_context(is_view: bool) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(AccountId::try_from("alice_near".to_string()).unwrap())
            .signer_account_id(AccountId::try_from("bob_near".to_string()).unwrap())
            .predecessor_account_id(AccountId::try_from("token_near".to_string()).unwrap())
            .block_index(1)
            .block_timestamp(1)
            .is_view(is_view)
            .build()
    }

    fn get_context_for_unlock(is_view: bool) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(AccountId::try_from("alice_near".to_string()).unwrap())
            .signer_account_id(AccountId::try_from("bob_near".to_string()).unwrap())
            .predecessor_account_id(AccountId::try_from("carol_near".to_string()).unwrap())
            .block_index(36003)
            .block_timestamp(1 + 3600000000000 + 2)
            .is_view(is_view)
            .build()
    }

    #[test]
    fn ft_on_transfer_with_empty_whitelist() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();

        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(100);
        contract.ft_on_transfer(transfer_account, balance, "".to_string());
    }

    #[test]
    fn ft_on_transfer_with_token_in_whitelist() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();

        let token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        contract.add_supported_token(token.clone());
        assert!(contract.whitelisted_tokens.contains(&token));

        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(100);
        contract.ft_on_transfer(transfer_account, balance, "".to_string());
    }

    #[test]
    #[should_panic]
    fn ft_on_transfer_with_token_not_in_whitelist() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();

        let token: AccountId = AccountId::try_from("token1_near".to_string()).unwrap();
        contract.add_supported_token(token.clone());
        assert!(contract.whitelisted_tokens.contains(&token));

        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(100);
        contract.ft_on_transfer(transfer_account, balance, "".to_string());
    }

    #[test]
    fn is_metadata_correct_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();

        let current_timestamp = block_timestamp() + contract.lock_time_min + 20;
        let mut msg: String = r#"
        {
            "chain_id": 5,
            "valid_till": "#
            .to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token_near": "alice_near",
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "100"
            },
            "fee": {
                "token": "alice_near",
                "amount": "100"
            },
            "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        }"#);

        let transfer_message = contract.is_metadata_correct(msg);

        let original = TransferMessage {
            chain_id: 5,
            valid_till: current_timestamp,
            transfer: TransferDataEthereum {
                token_near: AccountId::try_from("alice_near".to_string()).unwrap(),
                token_eth: get_eth_address("71C7656EC7ab88b098defB751B7401B5f6d8976F".to_string()),
                amount: U128(100),
            },
            fee: TransferDataNear {
                token: AccountId::try_from("alice_near".to_string()).unwrap(),
                amount: U128(100),
            },
            recipient: utils::get_eth_address(
                "71C7656EC7ab88b098defB751B7401B5f6d8976F".to_string(),
            ),
        };
        assert_eq!(
            serde_json::to_string(&original).unwrap(),
            serde_json::to_string(&transfer_message).unwrap()
        );
    }

    #[test]
    #[should_panic]
    fn metadata_not_correct_valid_time_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let current_timestamp = block_timestamp() - 20;
        let mut msg: String = r#"
        {
            "chain_id": 5,
            "valid_till": "#
            .to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token_near": "alice_near",
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "100"
            },
            "fee": {
                "token": "alice_near",
                "amount": "100"
            },
            "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        }"#);
        let _transfer_message = contract.is_metadata_correct(msg);
    }

    #[test]
    #[should_panic]
    fn metadata_lock_period_not_correct_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let current_timestamp = block_timestamp();
        let mut msg: String = r#"
        {
            "chain_id": 5,
            "valid_till": "#
            .to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token_near": "alice_near",
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "100"
            },
            "fee": {
                "token": "alice_near",
                "amount": "100"
            },
            "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        }"#);
        let _transfer_message = contract.is_metadata_correct(msg);
    }

    #[test]
    fn increase_balance_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();

        let balance = U128(100);

        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());
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

        let balance = U128(100);

        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(100, amount);

        contract.decrease_balance(&transfer_token, &balance.0);
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
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(200);

        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);

        let current_timestamp = block_timestamp() + contract.lock_time_min + 1;
        let mut msg: String = r#"
        {
            "chain_id": 5,
            "valid_till": "#
            .to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token_near": "token_near",
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "99"
            },
            "fee": {
                "token": "token_near",
                "amount": "99"
            },
             "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        }"#);
        contract.lock(msg);

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(2, transfer_token_amount);
    }

    #[test]
    fn unlock_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(100);

        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());
        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);

        let current_timestamp = block_timestamp() + contract.lock_time_min + 1;
        let mut msg: String = r#"
        {
            "chain_id": 5,
            "valid_till": "#
            .to_owned();
        msg.push_str(&current_timestamp.to_string());
        msg.push_str(r#",
            "transfer": {
                "token_near": "token_near",
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "75"
            },
            "fee": {
                "token": "token_near",
                "amount": "75"
            },
             "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        }"#);
        contract.lock(msg);

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(50, transfer_token_amount);

        let context = get_context_for_unlock(false);
        testing_env!(context);
        contract.unlock(1);
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);
    }

    #[test]
    fn set_current_chain_id() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = SpectreBridge::default();
        let new_current_chain_id = 33;

        assert_eq!(4, contract.current_chain_id);
        contract.set_current_chain_id(new_current_chain_id);
        assert_eq!(new_current_chain_id, contract.current_chain_id);
    }
}
