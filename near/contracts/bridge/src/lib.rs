use crate::lp_relayer::EthTransferEvent;
use near_plugins::{access_control, AccessControlRole, AccessControllable, Pausable};
use near_plugins_derive::pause;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};
use near_sdk::env::{block_timestamp, current_account_id};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use near_sdk::Promise;
use near_sdk::{
    env, ext_contract, is_promise_success, near_bindgen, require, AccountId, BorshStorageKey,
    Duration, PanicOnDefault, PromiseOrValue, PromiseResult,
};
use parse_duration::parse;
use spectre_bridge_common::*;
use whitelist::WhitelistMode;

pub use crate::ft::*;

mod ft;
mod lp_relayer;
mod utils;
mod whitelist;

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

#[ext_contract(ext_eth_client)]
pub trait EthClient {
    #[result_serializer(borsh)]
    fn last_block_number(&self) -> u64;
}

#[ext_contract(ext_token)]
trait NEP141Token {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[ext_contract(ext_self)]
trait SpectreBridgeInterface {
    fn withdraw_callback(&mut self, token_id: AccountId, amount: U128, sender_id: AccountId);
    fn verify_log_entry_callback(
        &mut self,
        #[serializer(borsh)] proof: EthTransferEvent,
    ) -> Promise;
    fn unlock_callback(
        &self,
        #[serializer(borsh)] nonce: U128,
        #[serializer(borsh)] sender_id: AccountId,
    );
    fn init_transfer_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] sender_id: AccountId,
    ) -> PromiseOrValue<U128>;
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct TransferData {
    token: AccountId,
    amount: u128,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct TransferMessage {
    valid_till: u64,
    transfer: TransferDataEthereum,
    fee: TransferDataNear,
    recipient: EthAddress,
    valid_till_block_height: Option<u64>,
}

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    PendingTransfers,
    UserBalances,
    UserBalancePrefix,
    WhitelistTokens,
    WhitelistAccounts,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct LockDuration {
    lock_time_min: Duration,
    lock_time_max: Duration,
}

#[derive(AccessControlRole, Deserialize, Serialize, Copy, Clone)]
#[serde(crate = "near_sdk::serde")]
pub enum Role {
    /// May pause and unpause features.
    PauseManager,
    /// May call `unlock` even when it is paused.
    UnrestrictedUnlock,
    /// May call `lp_unlock` even when it is paused.
    UnrestrictedLpUnlock,
}

#[access_control(role_type(Role))]
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault, Pausable)]
#[pausable(manager_roles(Role::PauseManager))]
pub struct SpectreBridge {
    pending_transfers: LookupMap<String, (AccountId, TransferMessage)>,
    user_balances: LookupMap<AccountId, LookupMap<AccountId, u128>>,
    nonce: u128,
    prover_account: AccountId,
    eth_client_account: AccountId,
    eth_bridge_contract: EthAddress,
    lock_duration: LockDuration,
    eth_block_time: Duration,
    /// Mapping whitelisted tokens to their mode
    whitelist_tokens: UnorderedMap<AccountId, WhitelistMode>,
    /// Mapping whitelisted accounts to their whitelisted tokens by using combined key {token}:{account}
    whitelist_accounts: UnorderedSet<String>,
    /// The mode of the whitelist check
    is_whitelist_mode_enabled: bool,
}

#[near_bindgen]
impl SpectreBridge {
    #[init]
    #[private]
    pub fn new(
        eth_bridge_contract: String,
        prover_account: AccountId,
        eth_client_account: AccountId,
        lock_time_min: String,
        lock_time_max: String,
        eth_block_time: Duration,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");

        let lock_time_min = parse(lock_time_min.as_str()).unwrap().as_nanos() as u64;
        let lock_time_max = parse(lock_time_max.as_str()).unwrap().as_nanos() as u64;
        require!(
            lock_time_max > lock_time_min,
            "Error initialize: lock_time_min must be less than lock_time_max"
        );

        let mut contract = Self {
            pending_transfers: LookupMap::new(StorageKey::PendingTransfers),
            user_balances: LookupMap::new(StorageKey::UserBalances),
            nonce: 0,
            prover_account,
            eth_client_account,
            eth_bridge_contract: get_eth_address(eth_bridge_contract),
            lock_duration: LockDuration {
                lock_time_min,
                lock_time_max,
            },
            eth_block_time,
            whitelist_tokens: UnorderedMap::new(StorageKey::WhitelistTokens),
            whitelist_accounts: UnorderedSet::new(StorageKey::WhitelistAccounts),
            is_whitelist_mode_enabled: true,
            __acl: Default::default(),
        };

        near_sdk::require!(
            contract.acl_init_super_admin(near_sdk::env::predecessor_account_id()),
            "Failed to initialize super admin",
        );
        contract
    }

    #[pause]
    pub fn init_transfer(&mut self, transfer_message: TransferMessage) -> PromiseOrValue<U128> {
        ext_eth_client::ext(self.eth_client_account.clone())
            .with_static_gas(utils::tera_gas(5))
            .last_block_number()
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(utils::tera_gas(200))
                    .init_transfer_callback(transfer_message, env::predecessor_account_id()),
            )
            .into()
    }

    #[private]
    pub fn init_transfer_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        last_block_height: u64,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] sender_id: AccountId,
    ) -> PromiseOrValue<U128> {
        let mut transfer_message = transfer_message;
        let lock_period = transfer_message.valid_till - block_timestamp();
        transfer_message.valid_till_block_height =
            Some(last_block_height + lock_period / self.eth_block_time);

        self.validate_transfer_message(&transfer_message, &sender_id);

        let user_token_balance = self.user_balances.get(&sender_id).unwrap_or_else(|| {
            panic!(
                "Balance in {} for user {} not found",
                transfer_message.transfer.token_near, sender_id
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
            token_transfer_balance >= u128::from(transfer_message.transfer.amount),
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
            token_fee_balance >= u128::from(transfer_message.fee.amount),
            "Not enough fee token balance."
        );

        self.decrease_balance(
            &sender_id,
            &transfer_message.transfer.token_near,
            &u128::from(transfer_message.transfer.amount),
        );

        self.decrease_balance(
            &sender_id,
            &transfer_message.fee.token,
            &u128::from(transfer_message.fee.amount),
        );

        let nonce = U128::from(self.store_transfers(sender_id, transfer_message.clone()));

        Event::SpectreBridgeInitTransferEvent {
            nonce,
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
            valid_till_block_height: transfer_message.valid_till_block_height.unwrap(),
        }
        .emit();

        PromiseOrValue::Value(nonce)
    }

    #[pause(except(roles(Role::UnrestrictedUnlock)))]
    pub fn unlock(&self, nonce: U128) -> Promise {
        ext_eth_client::ext(self.eth_client_account.clone())
            .with_static_gas(utils::tera_gas(5))
            .last_block_number()
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(utils::tera_gas(50))
                    .unlock_callback(nonce, env::predecessor_account_id()),
            )
    }

    #[private]
    pub fn unlock_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        last_block_height: u64,
        #[serializer(borsh)] nonce: U128,
        #[serializer(borsh)] sender_id: AccountId,
    ) {
        let transaction_id = utils::get_transaction_id(u128::try_from(nonce).unwrap());
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
            transfer.0 == sender_id,
            format!("Signer: {} transaction not found:", &sender_id)
        );
        require!(
            block_timestamp() > transfer_data.valid_till,
            "Valid time is not correct."
        );

        require!(
            last_block_height > transfer_data.valid_till_block_height.unwrap(),
            format!(
                "Minimum allowed block height is {}, but current client's block height is {}",
                transfer_data.valid_till_block_height.unwrap(),
                last_block_height
            )
        );

        self.increase_balance(
            &sender_id,
            &transfer_data.transfer.token_near,
            &u128::from(transfer_data.transfer.amount),
        );
        self.increase_balance(
            &sender_id,
            &transfer_data.fee.token,
            &u128::from(transfer_data.fee.amount),
        );
        self.pending_transfers.remove(&transaction_id);

        Event::SpectreBridgeUnlockEvent {
            nonce,
            account: sender_id,
        }
        .emit();
    }

    #[pause(except(roles(Role::UnrestrictedLpUnlock)))]
    pub fn lp_unlock(&mut self, proof: Proof) {
        let parsed_proof = lp_relayer::EthTransferEvent::parse(proof.clone());
        assert_eq!(
            parsed_proof.eth_bridge_contract,
            self.eth_bridge_contract,
            "Event's address {} does not match the eth bridge address {}",
            hex::encode(parsed_proof.eth_bridge_contract),
            hex::encode(self.eth_bridge_contract),
        );

        ext_prover::ext(self.prover_account.clone())
            .with_static_gas(utils::tera_gas(50))
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
                    .with_static_gas(utils::tera_gas(50))
                    .with_attached_deposit(utils::NO_DEPOSIT)
                    .verify_log_entry_callback(parsed_proof),
            );
    }

    #[private]
    pub fn verify_log_entry_callback(&mut self, #[serializer(borsh)] proof: EthTransferEvent) {
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

        let unlock_recipient = proof.unlock_recipient.parse().unwrap();
        self.increase_balance(
            &unlock_recipient,
            &transfer_data.transfer.token_near,
            &u128::from(transfer_data.transfer.amount),
        );
        self.increase_balance(
            &unlock_recipient,
            &transfer_data.fee.token,
            &u128::from(transfer_data.fee.amount),
        );
        self.pending_transfers.remove(&transaction_id);

        Event::SpectreBridgeUnlockEvent {
            nonce: U128(proof.nonce),
            account: unlock_recipient,
        }
        .emit();
    }

    pub fn get_user_balance(&self, account_id: &AccountId, token_id: &AccountId) -> u128 {
        let user_balance = self
            .user_balances
            .get(account_id)
            .unwrap_or_else(|| panic!("{}", "User doesn't have balance".to_string()));

        user_balance
            .get(token_id)
            .unwrap_or_else(|| panic!("User token: {} , balance is 0", token_id))
    }

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
            let storage_key = [
                StorageKey::UserBalancePrefix
                    .try_to_vec()
                    .unwrap()
                    .as_slice(),
                account_id.try_to_vec().unwrap().as_slice(),
            ]
            .concat();
            let mut token_balance = LookupMap::new(storage_key);
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

    fn decrease_balance(&mut self, user: &AccountId, token_id: &AccountId, amount: &u128) {
        let mut user_token_balance = self.user_balances.get(user).unwrap();
        let balance = user_token_balance.get(token_id).unwrap() - amount;
        user_token_balance.insert(token_id, &balance);
        self.user_balances.insert(user, &user_token_balance);
    }

    fn increase_balance(&mut self, user: &AccountId, token_id: &AccountId, amount: &u128) {
        let mut user_token_balance = self.user_balances.get(user).unwrap();
        let balance = user_token_balance.get(token_id).unwrap() + amount;
        user_token_balance.insert(token_id, &balance);
        self.user_balances.insert(user, &user_token_balance);
    }

    fn validate_transfer_message(&self, transfer_message: &TransferMessage, sender_id: &AccountId) {
        require!(
            transfer_message.valid_till > block_timestamp(),
            format!(
                "Transfer valid time:{} not correct, current block timestamp:{}.",
                transfer_message.valid_till,
                block_timestamp()
            )
        );

        let lock_period = transfer_message.valid_till - block_timestamp();
        require!(
            (self.lock_duration.lock_time_min..=self.lock_duration.lock_time_max)
                .contains(&lock_period),
            format!(
                "Lock period:{} does not fit the terms of the contract.",
                lock_period
            )
        );

        self.check_whitelist_token_and_account(&transfer_message.transfer.token_near, sender_id);
        self.check_whitelist_token_and_account(&transfer_message.fee.token, sender_id);
    }

    fn store_transfers(&mut self, sender_id: AccountId, transfer_message: TransferMessage) -> u128 {
        self.nonce += 1;
        let transaction_id = utils::get_transaction_id(self.nonce);
        let account_pending = (sender_id, transfer_message);
        self.pending_transfers
            .insert(&transaction_id, &account_pending);
        self.nonce
    }

    #[payable]
    #[pause]
    pub fn withdraw(&mut self, token_id: AccountId, amount: U128) {
        let sender_id = env::predecessor_account_id();
        let balance = self.get_user_balance(&sender_id, &token_id);

        require!(balance >= amount.into(), "Not enough token balance");

        ext_token::ext(token_id.clone())
            .with_static_gas(utils::tera_gas(5))
            .with_attached_deposit(1)
            .ft_transfer(
                sender_id.clone(),
                amount,
                Some(format!(
                    "Withdraw from: {} amount: {}",
                    current_account_id(),
                    u128::try_from(amount).unwrap()
                )),
            )
            .then(
                ext_self::ext(current_account_id())
                    .with_static_gas(utils::tera_gas(2))
                    .with_attached_deposit(utils::NO_DEPOSIT)
                    .withdraw_callback(token_id, amount, sender_id),
            );
    }

    #[private]
    pub fn withdraw_callback(&mut self, token_id: AccountId, amount: U128, sender_id: AccountId) {
        require!(is_promise_success(), "Error transfer");

        self.decrease_balance(&sender_id, &token_id, &u128::try_from(amount).unwrap());
    }

    #[private]
    pub fn set_prover_account(&mut self, prover_account: AccountId) {
        self.prover_account = prover_account;
    }

    #[private]
    pub fn set_enear_address(&mut self, near_address: String) {
        require!(
            utils::is_valid_eth_address(near_address.clone()),
            format!("Ethereum address:{} not valid.", near_address)
        );
        self.eth_bridge_contract = spectre_bridge_common::get_eth_address(near_address);
    }

    pub fn get_lock_duration(self) -> LockDuration {
        self.lock_duration
    }

    #[private]
    pub fn set_lock_time(&mut self, lock_time_min: String, lock_time_max: String) {
        let lock_time_min = parse(lock_time_min.as_str()).unwrap().as_nanos() as u64;
        let lock_time_max = parse(lock_time_max.as_str()).unwrap().as_nanos() as u64;

        self.lock_duration = LockDuration {
            lock_time_min,
            lock_time_max,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
    use near_sdk::env::{sha256, signer_account_id};
    use near_sdk::serde_json::{self, json};
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, VMContext};
    use std::convert::TryFrom;
    use uint::rustc_hex::ToHex;

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
            .block_index(200)
            //10800000000000 = lock_time_min
            .block_timestamp(1649402222 + 10800000000000 + 30)
            .is_view(is_view)
            .build()
    }

    fn get_context_dex(is_view: bool) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(AccountId::try_from("dex_near".to_string()).unwrap())
            .signer_account_id(AccountId::try_from("bob_near".to_string()).unwrap())
            .predecessor_account_id(AccountId::try_from("token_near2".to_string()).unwrap())
            .block_index(101)
            .block_timestamp(1649402222)
            .is_view(is_view)
            .build()
    }

    fn get_context_custom_signer(is_view: bool, signer: String) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(AccountId::try_from("dex_near".to_string()).unwrap())
            .signer_account_id(AccountId::try_from(signer).unwrap())
            .predecessor_account_id(AccountId::try_from("token_near".to_string()).unwrap())
            .block_index(101)
            .block_timestamp(1649402222)
            .is_view(is_view)
            .build()
    }

    fn get_context_custom_predecessor(is_view: bool, predecessor: String) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(AccountId::try_from("dex_near".to_string()).unwrap())
            .signer_account_id(AccountId::try_from("token_near".to_string()).unwrap())
            .predecessor_account_id(AccountId::try_from(predecessor).unwrap())
            .block_index(101)
            .block_timestamp(1649402222)
            .is_view(is_view)
            .build()
    }

    fn get_panic_context_for_unlock(is_view: bool) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(AccountId::try_from("bob_near".to_string()).unwrap())
            .signer_account_id(AccountId::try_from("dex_near".to_string()).unwrap())
            .predecessor_account_id(AccountId::try_from("carol_near".to_string()).unwrap())
            .block_index(200)
            //10800000000000 = lock_time_min
            .block_timestamp(1649402222 + 10800000000000 + 30)
            .is_view(is_view)
            .build()
    }

    macro_rules! inner_set_env {
        ($builder:ident) => {
            $builder
        };

        ($builder:ident, $key:ident:$value:expr $(,$key_tail:ident:$value_tail:expr)*) => {
            {
               $builder.$key($value.try_into().unwrap());
               inner_set_env!($builder $(,$key_tail:$value_tail)*)
            }
        };
    }

    macro_rules! set_env {
        ($($key:ident:$value:expr),* $(,)?) => {
            let mut builder = VMContextBuilder::new();
            let mut builder = &mut builder;
            builder = inner_set_env!(builder, $($key: $value),*);
            testing_env!(builder.build());
        };
    }

    /// Generate a valid ethereum address.
    fn ethereum_address_from_id(id: u8) -> String {
        let mut buffer = vec![id];
        sha256(buffer.as_mut())
            .into_iter()
            .take(20)
            .collect::<Vec<_>>()
            .to_hex()
    }

    struct BridgeInitArgs {
        eth_bridge_contract: Option<String>,
        prover_account: Option<AccountId>,
        eth_client_account: Option<AccountId>,
        lock_time_min: Option<String>,
        lock_time_max: Option<String>,
        whitelisted_tokens: Option<Vec<String>>,
    }

    fn get_bridge_config_v1() -> BridgeInitArgs {
        BridgeInitArgs {
            eth_bridge_contract: None,
            prover_account: None,
            eth_client_account: None,
            lock_time_min: Some(String::from("3h")),
            lock_time_max: Some(String::from("12h")),
            whitelisted_tokens: Some(tokens()),
        }
    }

    fn eth_bridge_address() -> String {
        "6b175474e89094c44da98b954eedeac495271d0f".to_string()
    }

    fn prover() -> AccountId {
        "prover.near".parse().unwrap()
    }

    fn eth_client() -> AccountId {
        "client.near".parse().unwrap()
    }

    fn tokens() -> Vec<String> {
        vec![
            "token_near".to_string(),
            "token_near2".to_string(),
            "alice_near".to_string(),
            "bob_near".to_string(),
            "token_near299".to_string(),
        ]
    }

    fn get_bridge_contract(config: Option<BridgeInitArgs>) -> SpectreBridge {
        let config = config.unwrap_or(BridgeInitArgs {
            eth_bridge_contract: None,
            prover_account: None,
            eth_client_account: None,
            lock_time_min: None,
            lock_time_max: None,
            whitelisted_tokens: Some(tokens()),
        });

        let mut contract = SpectreBridge::new(
            config.eth_bridge_contract.unwrap_or(eth_bridge_address()),
            config.prover_account.unwrap_or(prover()),
            config.eth_client_account.unwrap_or(eth_client()),
            config.lock_time_min.unwrap_or("1h".to_string()),
            config.lock_time_max.unwrap_or("24h".to_string()),
            12_000_000_000,
        );

        for token in config.whitelisted_tokens.unwrap_or(vec![]) {
            contract.set_token_whitelist_mode(token.parse().unwrap(), WhitelistMode::CheckToken);
        }

        contract
    }

    #[test]
    fn ft_on_transfer_with_empty_whitelist() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);

        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(100);
        contract.ft_on_transfer(transfer_account, balance, "".to_string());
    }

    #[test]
    fn ft_on_transfer_with_token_in_whitelist() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);

        let token: AccountId = AccountId::try_from("new_token_near".to_string()).unwrap();
        contract.set_token_whitelist_mode(token.clone(), WhitelistMode::CheckToken);
        assert!(contract.whitelist_tokens.get(&token).unwrap() == WhitelistMode::CheckToken);

        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(100);
        contract.ft_on_transfer(transfer_account, balance, "".to_string());
    }

    #[test]
    #[should_panic(expected = "The token `new_token.near` is not whitelisted")]
    fn ft_on_transfer_with_token_not_in_whitelist() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);

        let token: AccountId = AccountId::try_from("token1_near".to_string()).unwrap();
        contract.set_token_whitelist_mode(token.clone(), WhitelistMode::CheckToken);
        assert!(contract.whitelist_tokens.get(&token).unwrap() == WhitelistMode::CheckToken);

        let sender_account = accounts(1);
        let token_account: AccountId = AccountId::try_from("new_token.near".to_string()).unwrap();
        let balance = U128(100);

        set_env!(predecessor_account_id: token_account, signer_account_id: sender_account.clone());
        contract.ft_on_transfer(sender_account, balance, "".to_string());
    }

    #[test]
    fn is_metadata_correct_test() {
        let context = get_context(false);
        testing_env!(context);
        let contract = get_bridge_contract(None);

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 20;
        let token = "alice_near";
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": token,
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "100"
            },
            "fee": {
                "token": token,
                "amount": "100"
            },
            "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        });

        let transfer_message = serde_json::from_value(msg).unwrap();
        contract.validate_transfer_message(&transfer_message, &"bob_near".parse().unwrap());

        let original = TransferMessage {
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
            recipient: spectre_bridge_common::get_eth_address(
                "71C7656EC7ab88b098defB751B7401B5f6d8976F".to_string(),
            ),
            valid_till_block_height: None,
        };
        assert_eq!(
            serde_json::to_string(&original).unwrap(),
            serde_json::to_string(&transfer_message).unwrap()
        );
    }

    #[test]
    #[should_panic(expected = "attempt to subtract with overflow")]
    fn metadata_not_correct_valid_time_test() {
        let context = get_context(false);
        testing_env!(context);
        let contract = get_bridge_contract(None);
        let current_timestamp = block_timestamp() - 20;
        let token = "alice_near";
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": token,
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "100"
            },
            "fee": {
                "token": token,
                "amount": "100"
            },
            "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        });

        contract.validate_transfer_message(
            &serde_json::from_value(msg).unwrap(),
            &token.parse().unwrap(),
        );
    }

    #[test]
    #[should_panic(expected = "not correct, current block timestamp")]
    fn metadata_lock_period_not_correct_test() {
        let context = get_context(false);
        testing_env!(context);
        let contract = get_bridge_contract(None);
        let current_timestamp = block_timestamp();
        let token = "alice_near";
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": token,
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "100"
            },
            "fee": {
                "token": token,
                "amount": "100"
            },
            "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        });

        contract.validate_transfer_message(
            &serde_json::from_value(msg).unwrap(),
            &"bob.near".parse().unwrap(),
        );
    }

    #[test]
    fn increase_balance_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
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
        let mut contract = get_bridge_contract(None);
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();

        let balance = U128(100);

        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(100, amount);

        contract.decrease_balance(&signer_account_id(), &transfer_token, &balance.0);
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(0, amount);
    }

    #[test]
    fn lock_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(200);

        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 1;
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": "token_near",
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "100"
            },
            "fee": {
                "token": "token_near",
                "amount": "100"
            },
             "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        });

        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
        );

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(0, transfer_token_amount);
    }

    #[test]
    fn unlock_test() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(100);

        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());
        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 1;
        let msg = json!({
            "valid_till": current_timestamp,
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
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
        );

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(50, transfer_token_amount);

        let context = get_context_for_unlock(false);
        testing_env!(context);
        let nonce = U128(1);
        contract.unlock_callback(312, nonce, signer_account_id());
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);
    }

    //audit tests
    #[test]
    #[should_panic(expected = r#"Balance in token_near for user bob_near not found"#)]
    fn test_lock_no_balance() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(Some(get_bridge_config_v1()));

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 20;
        let msg = json!({
            "valid_till": current_timestamp,
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
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
        );
    }

    #[test]
    #[should_panic(expected = r#"Balance for token transfer: token_near299 not found"#)]
    fn test_lock_balance_not_found() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(Some(get_bridge_config_v1()));

        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_token2: AccountId = AccountId::try_from("token_near2".to_string()).unwrap();
        let balance: u128 = 100;

        contract.ft_on_transfer(
            signer_account_id(),
            U128(balance),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token, balance
            ),
        );
        contract.ft_on_transfer(
            signer_account_id(),
            U128(balance),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token2, balance
            ),
        );

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 20;
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": "token_near299",
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "75"
            },
            "fee": {
                "token": "token_near",
                "amount": "75"
            },
             "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
        );
    }

    #[test]
    #[should_panic(expected = r#"Balance for token fee: token_near not found"#)]
    fn test_lock_fee_balance_not_found() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(Some(get_bridge_config_v1()));

        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_token2: AccountId = AccountId::try_from("token_near2".to_string()).unwrap();
        let balance: u128 = 100;

        let context = get_context_custom_signer(false, "token_near".to_string());
        testing_env!(context);
        contract.ft_on_transfer(
            signer_account_id(),
            U128(balance),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token, balance
            ),
        );

        let context = get_context_custom_signer(false, "token_near2".to_string());
        testing_env!(context);
        contract.ft_on_transfer(
            signer_account_id(),
            U128(balance),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token2, balance
            ),
        );

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 20;
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": "token_near",
                "token_eth": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111],
                "amount": "75"
            },
            "fee": {
                "token": "token_near299",
                "amount": "75"
            },
             "recipient": [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111]
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
        );
    }

    #[test]
    #[should_panic(expected = r#"Transaction with id:"#)]
    fn test_unlock_transaction_not_found() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(Some(get_bridge_config_v1()));
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_token2: AccountId = AccountId::try_from("token_near2".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap(); // signer account
        let balance: u128 = 100;

        contract.ft_on_transfer(
            signer_account_id(),
            U128(balance),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token, balance
            ),
        );

        contract.ft_on_transfer(
            signer_account_id(),
            U128(balance),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token2, balance
            ),
        );

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 20;
        let msg = json!({
            "valid_till": current_timestamp,
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
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
        );

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(50, transfer_token_amount);

        let context = get_context_for_unlock(false);
        testing_env!(context);
        contract.unlock_callback(10, U128(9), signer_account_id());
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);
    }

    #[test]
    #[should_panic(expected = r#"Signer: dex_near transaction not found:"#)]
    fn test_unlock_invalid_account() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(Some(get_bridge_config_v1()));
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_token2: AccountId = AccountId::try_from("token_near2".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance: u128 = 100;

        contract.ft_on_transfer(
            signer_account_id(),
            U128(balance),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token, balance
            ),
        );
        let context = get_context_dex(false);
        testing_env!(context);
        contract.ft_on_transfer(
            signer_account_id(),
            U128(balance),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token2, balance
            ),
        );
        let user_balance = contract.user_balances.get(&signer_account_id()).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();

        assert_eq!(100, transfer_token_amount);

        let context = get_context(false);
        testing_env!(context);
        contract.ft_on_transfer(
            signer_account_id(),
            U128(balance),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token2, balance
            ),
        );
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();

        assert_eq!(200, transfer_token_amount);

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 20;
        let msg = json!({
            "valid_till": current_timestamp,
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
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
        );

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(50, transfer_token_amount);

        let context = get_panic_context_for_unlock(false);
        testing_env!(context);
        contract.unlock_callback(10, U128(1), signer_account_id());
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);
    }

    #[test]
    #[should_panic(expected = r#"User doesn't have balance"#)]
    fn test_withdraw_no_balance() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let amount = 42;
        contract.withdraw(transfer_token, U128(amount));
    }

    #[test]
    #[should_panic(expected = r#"User doesn't have balance"#)]
    fn test_withdraw_wrong_balance() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let transfer_token: AccountId = AccountId::try_from("token_near2".to_string()).unwrap();
        let amount = 42;
        let context = get_context_custom_signer(false, transfer_token.to_string());
        testing_env!(context);
        contract.ft_on_transfer(
            transfer_token.clone(),
            U128(amount),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token, amount
            ),
        );
        let context = get_context_custom_predecessor(false, String::from("token_near"));
        testing_env!(context);
        contract.withdraw(transfer_token, U128(amount));
    }

    #[test]
    #[should_panic(expected = r#"Not enough token balance"#)]
    fn test_withdraw_not_enough_balance() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let amount = 42;
        let context = get_context_custom_signer(false, String::from("token_near"));
        testing_env!(context);
        contract.ft_on_transfer(
            transfer_token.clone(),
            U128(amount),
            format!(
                "Was transferred token:{}, amount:{}",
                transfer_token, amount
            ),
        );

        let context = get_context(false);
        testing_env!(context);
        contract.withdraw(transfer_token, U128(amount + 1));
    }

    #[test]
    #[should_panic(expected = r#"Contract expected a result on the callback"#)]
    fn test_withdraw_callback() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let token_id: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let amount = 42;
        contract.withdraw_callback(token_id, U128(amount), signer_account_id());
    }

    #[test]
    #[should_panic(expected = r#"Ethereum address:test_addr not valid"#)]
    fn test_set_enear_address_invalid_address() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let invalid_address = "test_addr".to_string();
        contract.set_enear_address(invalid_address);
    }

    #[test]
    fn test_set_enear_address() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let valid_address: String = "42".repeat(20);
        let valid_eth_address: Vec<u8> = hex::decode(valid_address.clone()).unwrap();
        contract.set_enear_address(valid_address);

        assert_eq!(contract.eth_bridge_contract, valid_eth_address[..]);
    }

    #[test]
    fn test_set_lock_time() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let lock_time_min = "420h".to_string();
        let lock_time_max = "42h".to_string();
        let convert_nano = 36 * u64::pow(10, 11);
        contract.set_lock_time(lock_time_min, lock_time_max);

        assert_eq!(
            contract.lock_duration.lock_time_min as u64 / convert_nano,
            420
        );
        assert_eq!(
            contract.lock_duration.lock_time_max as u64 / convert_nano,
            42
        );
    }

    #[test]
    fn test_update_balance() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let tokens: [AccountId; 3] = [
            "token1.near".parse().unwrap(),
            "token2.near".parse().unwrap(),
            "token3.near".parse().unwrap(),
        ];
        let users: [AccountId; 3] = [
            "user1.near".parse().unwrap(),
            "user2.near".parse().unwrap(),
            "user3.near".parse().unwrap(),
        ];

        for user in users.iter() {
            for token in tokens.iter() {
                for _ in 0..3 {
                    contract.update_balance(user.clone(), token.clone(), 10);
                }
            }
        }

        for user in users.iter() {
            for token in tokens.iter() {
                for _ in 0..3 {
                    assert_eq!(contract.get_user_balance(user, token), 30);
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "is blocked")]
    fn test_blocked_token() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = get_bridge_contract(None);

        let token_account = accounts(1);
        let sender_account = accounts(2);
        set_env!(predecessor_account_id: token_account.clone(), signer_account_id: sender_account.clone());
        contract.set_token_whitelist_mode(token_account, WhitelistMode::Blocked);
        contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
    }

    #[test]
    #[should_panic(expected = "isn't whitelisted for the account")]
    fn test_account_not_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = get_bridge_contract(None);

        let token_account = accounts(1);
        let sender_account = accounts(2);
        set_env!(predecessor_account_id: token_account, signer_account_id: sender_account.clone());
        contract.set_token_whitelist_mode(accounts(1), WhitelistMode::CheckAccountAndToken);
        contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
    }

    #[test]
    #[should_panic(expected = "is not whitelisted")]
    fn test_token_not_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = get_bridge_contract(None);

        let token_account = accounts(1);
        let sender_account = accounts(2);
        set_env!(predecessor_account_id: token_account, signer_account_id: sender_account.clone());
        contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
    }

    #[test]
    fn test_account_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = get_bridge_contract(None);

        let token_account = accounts(1);
        let sender_account = accounts(2);
        contract
            .set_token_whitelist_mode(token_account.clone(), WhitelistMode::CheckAccountAndToken);
        contract
            .add_token_to_account_whitelist(Some(token_account.clone()), sender_account.clone());

        set_env!(predecessor_account_id: token_account, signer_account_id: sender_account.clone());
        contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
    }

    #[test]
    #[should_panic(expected = "isn't whitelisted for the account")]
    fn test_remove_account_from_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = get_bridge_contract(None);

        let token_account = accounts(1);
        let sender_account = accounts(2);
        contract
            .set_token_whitelist_mode(token_account.clone(), WhitelistMode::CheckAccountAndToken);
        contract
            .add_token_to_account_whitelist(Some(token_account.clone()), sender_account.clone());

        set_env!(predecessor_account_id: token_account.clone(), signer_account_id: sender_account.clone());
        contract.ft_on_transfer(
            sender_account.clone(),
            U128(1_000_000),
            ethereum_address_from_id(0),
        );

        contract.remove_token_from_account_whitelist(
            Some(token_account.clone()),
            sender_account.clone(),
        );
        contract.ft_on_transfer(
            sender_account.clone(),
            U128(1_000_000),
            ethereum_address_from_id(0),
        );
    }

    #[test]
    fn test_tokens_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = get_bridge_contract(None);

        let whitelist_tokens = ["token1.near", "token2.near", "token3.near"];

        for token_id in whitelist_tokens {
            contract.set_token_whitelist_mode(token_id.parse().unwrap(), WhitelistMode::CheckToken);
        }

        for token_id in whitelist_tokens {
            let token_account: AccountId = token_id.parse().unwrap();
            let sender_account = accounts(2);
            set_env!(predecessor_account_id: token_account, signer_account_id: sender_account.clone());
            contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
        }
    }

    #[test]
    fn test_accounts_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = get_bridge_contract(None);

        let whitelist_tokens = ["token1.near", "token2.near", "token3.near"];
        let whitelist_accounts = ["account1.near", "account2.near", "account3.near"];

        for token_id in whitelist_tokens {
            let token_account: AccountId = token_id.parse().unwrap();
            contract.set_token_whitelist_mode(
                token_account.clone(),
                WhitelistMode::CheckAccountAndToken,
            );

            for account_id in whitelist_accounts {
                let sender_account: AccountId = account_id.parse().unwrap();
                contract.add_token_to_account_whitelist(
                    Some(token_account.clone()),
                    sender_account.clone(),
                );
            }
        }

        for token_id in whitelist_tokens {
            for account_id in whitelist_accounts {
                let token_account: AccountId = token_id.parse().unwrap();
                let sender_account: AccountId = account_id.parse().unwrap();
                set_env!(predecessor_account_id: token_account, signer_account_id: sender_account.clone());
                contract.ft_on_transfer(
                    sender_account,
                    U128(1_000_000),
                    ethereum_address_from_id(0),
                );
            }
        }
    }
}
