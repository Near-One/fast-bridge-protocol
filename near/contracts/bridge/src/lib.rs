use crate::lp_relayer::EthTransferEvent;
use fast_bridge_common::*;
use near_plugins::{access_control, AccessControlRole, AccessControllable, Pausable};
use near_plugins_derive::{access_control_any, pause};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedMap, UnorderedSet};
use near_sdk::env::{block_timestamp, current_account_id};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use near_sdk::Promise;
use near_sdk::{
    env, ext_contract, is_promise_success, near_bindgen, require, AccountId, BorshStorageKey,
    Duration, PanicOnDefault, PromiseOrValue,
};
use parse_duration::parse;
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

    #[result_serializer(borsh)]
    fn verify_account_proof(
        &self,
        #[serializer(borsh)] header_data: Vec<u8>,
        #[serializer(borsh)] proof: Vec<Vec<u8>>, // account proof
        #[serializer(borsh)] key: Vec<u8>,  // keccak256 of eth address
        #[serializer(borsh)] account_data: Vec<u8>,  // rlp encoded account state
        #[serializer(borsh)] skip_bridge_call: bool
    ) -> PromiseOrValue<bool>;
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
trait FastBridgeInterface {
    fn withdraw_callback(&mut self, token_id: AccountId, amount: U128, sender_id: AccountId);
    fn verify_log_entry_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] proof: EthTransferEvent,
    ) -> Promise;
    fn verify_account_proof_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] transaction_id: String,
        #[serializer(borsh)] recipient_id: AccountId,
        #[serializer(borsh)] transfer_data: TransferMessage,
        #[serializer(borsh)] nonce: U128,
    ) -> Promise;
    fn unlock_callback(
        &self,
        #[serializer(borsh)] nonce: U128,
        #[serializer(borsh)] recipient_id: AccountId,
        #[serializer(borsh)] proof: UnlockProof,
    );
    fn init_transfer_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] update_balance: Option<UpdateBalance>,
    ) -> PromiseOrValue<U128>;
}

#[derive(Default, BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize, PartialEq,)]
pub struct UnlockProof {
    header_data: Vec<u8>,
    proof: Vec<Vec<u8>>,
    key: Vec<u8>,  
    account_data: Vec<u8>,
    processed_hash: Vec<u8>,
    value: bool
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct UpdateBalance {
    sender_id: AccountId,
    token: AccountId,
    amount: U128,
}

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    PendingTransfers,
    UserBalances,
    UserBalancePrefix,
    WhitelistTokens,
    WhitelistAccounts,
    PendingTransfersBalances,
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
    /// May call `withdraw` even when it is paused.
    UnrestrictedWithdraw,
    WhitelistManager,
    ConfigManager,
}

#[access_control(role_type(Role))]
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault, Pausable)]
#[pausable(manager_roles(Role::PauseManager))]
pub struct FastBridge {
    pending_transfers: UnorderedMap<String, (AccountId, TransferMessage)>,
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
    pending_transfers_balances: UnorderedMap<AccountId, u128>,
}


#[near_bindgen]
impl FastBridge {
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

        let lock_time_min: u64 = parse(lock_time_min.as_str())
            .unwrap()
            .as_nanos()
            .try_into()
            .unwrap();
        let lock_time_max: u64 = parse(lock_time_max.as_str())
            .unwrap()
            .as_nanos()
            .try_into()
            .unwrap();

        require!(
            lock_time_max > lock_time_min,
            "Error initialize: lock_time_min must be less than lock_time_max"
        );

        let mut contract = Self {
            pending_transfers: UnorderedMap::new(StorageKey::PendingTransfers),
            pending_transfers_balances: UnorderedMap::new(StorageKey::PendingTransfersBalances),
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
    pub fn init_transfer(
        &mut self,
        msg: near_sdk::json_types::Base64VecU8,
    ) -> PromiseOrValue<U128> {
        let transfer_message = TransferMessage::try_from_slice(&msg.0)
            .unwrap_or_else(|_| env::panic_str("Invalid borsh format of the `TransferMessage`"));
        self.init_transfer_internal(transfer_message, env::predecessor_account_id(), None)
            .into()
    }

    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        sender_id: AccountId,
        update_balance: Option<UpdateBalance>,
    ) -> Promise {
        near_sdk::env::log_str(&near_sdk::serde_json::to_string(&transfer_message).unwrap());
        ext_eth_client::ext(self.eth_client_account.clone())
            .with_static_gas(utils::tera_gas(5))
            .last_block_number()
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(utils::tera_gas(200))
                    .init_transfer_callback(transfer_message, sender_id, update_balance),
            )
    }

    #[private]
    pub fn init_transfer_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        last_block_height: u64,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] update_balance: Option<UpdateBalance>,
    ) -> U128 {
        #[cfg(feature = "disable_different_fee_token")]
        require!(
            transfer_message.fee.token == transfer_message.transfer.token_near,
            "The fee token does not match the transfer token"
        );

        if let Some(update_balance) = update_balance.as_ref() {
            self.increase_balance(
                &update_balance.sender_id,
                &update_balance.token,
                &update_balance.amount.0,
            );
        }

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

        self.decrease_balance(
            &sender_id,
            &transfer_message.transfer.token_near,
            &u128::from(transfer_message.transfer.amount),
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
            &transfer_message.fee.token,
            &u128::from(transfer_message.fee.amount),
        );

        let nonce = U128::from(self.store_transfers(sender_id.clone(), transfer_message.clone()));

        if let Some(update_balance) = update_balance {
            Event::FastBridgeDepositEvent {
                sender_id: update_balance.sender_id,
                token: update_balance.token,
                amount: update_balance.amount,
            }
            .emit();
        }

        Event::FastBridgeInitTransferEvent {
            nonce,
            sender_id,
            transfer_message,
        }
        .emit();

        U128::from(0)
    }

    #[pause(except(roles(Role::UnrestrictedUnlock)))]
    pub fn unlock(&self, nonce: U128, proof: UnlockProof) -> Promise {
        let cloned_proof = proof.clone();
        ext_prover::ext(self.prover_account.clone())
            .with_static_gas(utils::tera_gas(50))
            .with_attached_deposit(utils::NO_DEPOSIT)
            .verify_account_proof(
                proof.header_data,
                proof.proof,
                proof.key,
                proof.account_data,
                false
            )
            .then(
                ext_self::ext(current_account_id())
                    .with_static_gas(utils::tera_gas(50))
                    .with_attached_deposit(utils::NO_DEPOSIT)
                    .unlock_callback(nonce, env::predecessor_account_id(), cloned_proof),
            )
    }

    #[private]
    pub fn unlock_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_result: bool,
        #[serializer(borsh)] nonce: U128,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] proof: UnlockProof,
    ) {
        require!(proof.value, "transfer has been processed");
        let transaction_id = utils::get_transaction_id(u128::try_from(nonce).unwrap());
        let (recipient_id, transfer_data) = self
            .pending_transfers
            .get(&transaction_id)
            .unwrap_or_else(|| {
                panic!(
                    "Transaction with id: {} not found",
                    &transaction_id.to_string()
                )
            });

        let is_unlock_allowed = recipient_id == sender_id
            || self.acl_has_role("UnrestrictedUnlock".to_string(), sender_id.clone());

        require!(
            is_unlock_allowed,
            format!("Permission denied for account: {}", sender_id)
        );
        require!(
            block_timestamp() > transfer_data.valid_till,
            "Valid time is not correct."
        );

        require!(
            verification_result,
            format!(
                "Verification failed for unlock proof"
            )
        );
        
        require!((utils::get_processed_hash(transfer_data.clone(), nonce).to_vec()).eq(&proof.processed_hash), "User input processedHash incorrect");

        self.increase_balance(
            &recipient_id,
            &transfer_data.transfer.token_near,
            &u128::from(transfer_data.transfer.amount),
        );
        self.increase_balance(
            &recipient_id,
            &transfer_data.fee.token,
            &u128::from(transfer_data.fee.amount),
        );
        self.remove_transfer(&transaction_id, &transfer_data);

        Event::FastBridgeUnlockEvent {
            nonce,
            recipient_id,
            transfer_message: transfer_data,
        }
        .emit();  

    }


    #[pause(except(roles(Role::UnrestrictedLpUnlock)))]
    pub fn lp_unlock(&mut self, proof: Proof) -> Promise {
        let parsed_proof = lp_relayer::EthTransferEvent::parse(proof.clone());
        assert_eq!(
            parsed_proof.eth_bridge_contract,
            self.eth_bridge_contract,
            "Event's address {} does not match the eth bridge address {}",
            eth_encode_packed::hex::encode(parsed_proof.eth_bridge_contract),
            eth_encode_packed::hex::encode(self.eth_bridge_contract),
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
            )
    }

    #[private]
    pub fn verify_log_entry_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_success: bool,
        #[serializer(borsh)] proof: EthTransferEvent,
    ) {
        require!(verification_success, "Failed to verify the proof");

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

        let recipient_id = proof.unlock_recipient.parse().unwrap();
        self.increase_balance(
            &recipient_id,
            &transfer_data.transfer.token_near,
            &u128::from(transfer_data.transfer.amount),
        );
        self.increase_balance(
            &recipient_id,
            &transfer_data.fee.token,
            &u128::from(transfer_data.fee.amount),
        );
        self.remove_transfer(&transaction_id, &transfer_data);

        Event::FastBridgeLpUnlockEvent {
            nonce: U128(proof.nonce),
            recipient_id,
            transfer_message: transfer_data,
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

    fn decrease_balance(&mut self, user: &AccountId, token_id: &AccountId, amount: &u128) {
        let mut user_token_balance = self.user_balances.get(user).unwrap();
        let balance = user_token_balance.get(token_id).unwrap() - amount;
        user_token_balance.insert(token_id, &balance);
        self.user_balances.insert(user, &user_token_balance);
    }

    fn increase_balance(&mut self, user: &AccountId, token_id: &AccountId, amount: &u128) {
        if let Some(mut user_balances) = self.user_balances.get(user) {
            user_balances.insert(
                token_id,
                &(user_balances.get(token_id).unwrap_or(0) + amount),
            );
        } else {
            let storage_key = [
                StorageKey::UserBalancePrefix
                    .try_to_vec()
                    .unwrap()
                    .as_slice(),
                user.try_to_vec().unwrap().as_slice(),
            ]
            .concat();
            let mut token_balance = LookupMap::new(storage_key);
            token_balance.insert(token_id, amount);
            self.user_balances.insert(user, &token_balance);
        }
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
        let new_balance = self
            .pending_transfers_balances
            .get(&transfer_message.transfer.token_near)
            .unwrap_or(0)
            + transfer_message.transfer.amount.0;

        self.pending_transfers_balances
            .insert(&transfer_message.transfer.token_near, &new_balance);

        self.nonce += 1;
        let transaction_id = utils::get_transaction_id(self.nonce);
        let account_pending = (sender_id, transfer_message);
        self.pending_transfers
            .insert(&transaction_id, &account_pending);
        self.nonce
    }

    fn remove_transfer(&mut self, transfer_id: &String, transfer_message: &TransferMessage) {
        let new_balance = self
            .pending_transfers_balances
            .get(&transfer_message.transfer.token_near)
            .unwrap_or_else(|| env::panic_str("Pending balance does not exist"))
            - transfer_message.transfer.amount.0;

        self.pending_transfers_balances
            .insert(&transfer_message.transfer.token_near, &new_balance);

        self.pending_transfers.remove(transfer_id);
    }

    #[payable]
    #[pause(except(roles(Role::UnrestrictedWithdraw)))]
    pub fn withdraw(&mut self, token_id: AccountId, amount: U128) {
        let receiver_id = env::predecessor_account_id();
        let balance = self.get_user_balance(&receiver_id, &token_id);

        require!(balance >= amount.into(), "Not enough token balance");

        ext_token::ext(token_id.clone())
            .with_static_gas(utils::tera_gas(5))
            .with_attached_deposit(1)
            .ft_transfer(
                receiver_id.clone(),
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
                    .withdraw_callback(token_id, amount, receiver_id),
            );
    }

    #[private]
    pub fn withdraw_callback(&mut self, token_id: AccountId, amount: U128, sender_id: AccountId) {
        require!(is_promise_success(), "Error transfer");

        self.decrease_balance(&sender_id, &token_id, &u128::try_from(amount).unwrap());

        Event::FastBridgeWithdrawEvent {
            recipient_id: sender_id,
            token: token_id,
            amount,
        }
        .emit();
    }

    #[access_control_any(roles(Role::ConfigManager))]
    pub fn set_prover_account(&mut self, prover_account: AccountId) {
        self.prover_account = prover_account;
    }

    #[access_control_any(roles(Role::ConfigManager))]
    pub fn set_enear_address(&mut self, near_address: String) {
        require!(
            utils::is_valid_eth_address(near_address.clone()),
            format!("Ethereum address:{} not valid.", near_address)
        );
        self.eth_bridge_contract = fast_bridge_common::get_eth_address(near_address);
    }

    pub fn get_lock_duration(self) -> LockDuration {
        self.lock_duration
    }

    pub fn get_pending_balance(&self, token_id: AccountId) -> u128 {
        self.pending_transfers_balances.get(&token_id).unwrap_or(0)
    }

    pub fn get_pending_transfers(
        &self,
        from_index: usize,
        limit: usize,
    ) -> Vec<(String, (AccountId, TransferMessage))> {
        self.pending_transfers
            .iter()
            .skip(from_index)
            .take(limit)
            .collect::<Vec<_>>()
    }

    pub fn get_pending_transfer(&self, id: String) -> Option<(AccountId, TransferMessage)> {
        self.pending_transfers.get(&id)
    }

    #[access_control_any(roles(Role::ConfigManager))]
    pub fn set_lock_time(&mut self, lock_time_min: String, lock_time_max: String) {
        let lock_time_min: u64 = parse(lock_time_min.as_str())
            .unwrap()
            .as_nanos()
            .try_into()
            .unwrap();
        let lock_time_max: u64 = parse(lock_time_max.as_str())
            .unwrap()
            .as_nanos()
            .try_into()
            .unwrap();

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

    fn get_bridge_contract(config: Option<BridgeInitArgs>) -> FastBridge {
        let config = config.unwrap_or(BridgeInitArgs {
            eth_bridge_contract: None,
            prover_account: None,
            eth_client_account: None,
            lock_time_min: None,
            lock_time_max: None,
            whitelisted_tokens: Some(tokens()),
        });

        let mut contract = FastBridge::new(
            config.eth_bridge_contract.unwrap_or(eth_bridge_address()),
            config.prover_account.unwrap_or(prover()),
            config.eth_client_account.unwrap_or(eth_client()),
            config.lock_time_min.unwrap_or("1h".to_string()),
            config.lock_time_max.unwrap_or("24h".to_string()),
            12_000_000_000,
        );

        contract.acl_grant_role("WhitelistManager".to_string(), "alice".parse().unwrap());
        contract.acl_grant_role(
            "WhitelistManager".to_string(),
            "token_near".parse().unwrap(),
        );
        for token in config.whitelisted_tokens.unwrap_or(vec![]) {
            contract.set_token_whitelist_mode(token.parse().unwrap(), WhitelistMode::CheckToken);
        }

        contract
    }

    fn encode_message(transfer_message_json_str: &str) -> String {
        let output = std::process::Command::new("cargo")
            .args([
                "run",
                "--manifest-path",
                "../../utils/Cargo.toml",
                "--",
                "encode-transfer-msg",
                "-m",
                transfer_message_json_str,
            ])
            .output()
            .expect("failed to execute process");

        String::from_utf8_lossy(&output.stdout)
            .trim()
            .lines()
            .last()
            .unwrap()
            .trim_matches('"')
            .to_string()
    }

    fn generate_unlock_proof(header_data: &str, account_data: &str, key: &str, proof: Vec<&str>, processed_hash: &str, value: bool) -> UnlockProof{
        let header = eth_encode_packed::hex::decode(header_data).unwrap().into();
        let account = eth_encode_packed::hex::decode(account_data).unwrap().into();
        let key = eth_encode_packed::hex::decode(key).unwrap().into(); 
        let account_proof = proof.into_iter().map(|x| eth_encode_packed::hex::decode(x).unwrap()).collect();
        let ph = eth_encode_packed::hex::decode(processed_hash).unwrap().into();
        let unlock_proof = UnlockProof{header_data: header, proof: account_proof, key: key, account_data: account, processed_hash: ph, value: value};
        unlock_proof

    }

    #[test]
    fn test_ft_on_transfer_with_message() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);

        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(100);
        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 1;
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": "token_near",
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "75"
            },
            "fee": {
                "token": "token_near",
                "amount": "75"
            },
             "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
        });

        contract.ft_on_transfer(
            transfer_account,
            balance,
            encode_message(serde_json::to_string(&msg).unwrap().as_str()),
        );
    }

    #[test]
    #[should_panic(expected = "Invalid base64 message")]
    fn test_panic_on_invalid_transfer_message() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);

        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(100);
        contract.ft_on_transfer(
            transfer_account,
            balance,
            "0000MEYDAAAKAAAAdG9rZW5fbmVhcnHHZW7Hq4iwmN77dRt0AbX22JdvSwAAAAAAAAAAAAAAAAAAAAoAAAB0b2tlbl9uZWFySwAAAAAAAAAAAAAAAAAAAHHHZW7Hq4iwmN77dRt0AbX22JdvAA====".to_owned(),
        );
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
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "100"
            },
            "fee": {
                "token": token,
                "amount": "100"
            },
            "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
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
            recipient: fast_bridge_common::get_eth_address(
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
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "100"
            },
            "fee": {
                "token": token,
                "amount": "100"
            },
            "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
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
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "100"
            },
            "fee": {
                "token": token,
                "amount": "100"
            },
            "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
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
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "100"
            },
            "fee": {
                "token": "token_near",
                "amount": "100"
            },
             "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
        });

        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
            None,
        );

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(0, transfer_token_amount);
    }

    #[test]
    #[should_panic(expected = "Not enough fee token balance")]
    fn test_init_transfer_on_not_enough_fee_token_balance() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let transfer_token_amount = 150;

        contract.ft_on_transfer(
            transfer_account.clone(),
            U128(transfer_token_amount),
            "".to_string(),
        );

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let user_balance_for_transfer_token = user_balance.get(&transfer_token).unwrap();
        assert_eq!(transfer_token_amount, user_balance_for_transfer_token);

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 1;
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": "token_near",
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "100"
            },
            "fee": {
                "token": "token_near",
                "amount": "100"
            },
             "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
        });

        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
            None,
        );
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
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "75"
            },
            "fee": {
                "token": "token_near",
                "amount": "75"
            },
             "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
            None,
        );

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(50, transfer_token_amount);

        let context = get_context_for_unlock(false);
        testing_env!(context);

        let header  = "f9021ba0695d799c7fbeda2651dd907991909e4ae68612851ce5398f2efc9506e69247cda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b64a30399f7f6b0c154c2e7af0a3ec7b0a5b131aa0eea9136af6ad8b65ad4c2184bbe6ab400f1ae214ed069d56d89639d7329d083ea063bbd1ab5c4e3922601b38d701e091e1ad3bc30a8e6e6a166728a6b5c9a61d31a0108126d36fb961af5e2d8359a6fced486e368965bbcba286205983dd06011aceb901000120011010a05000008a4800841200c0042918c020a44820008210109a02018c028d000000004001009a014c1085c000430019108410580008041204143226407a2001200470804449a0620802440121001124020cc07a040318018480a146110002528216204104220200806080086020c018a02000120020204818800000504604c1200000202100004003a188820624281c212102000901010d6051ec081002001a0000c8041010806460121600222104002188072024090001c60020088d2060c8ca500a1224161090040c82620c014060040608011048a1401010803004ba159d5800002802000300c241100296888004086a0030c015003b0212003004308380ffb58401c9c38083f281638463e31ac89f496c6c756d696e61746520446d6f63726174697a6520447374726962757465a086a600953aa2865ceb8c7a6348f388aaad93ca30c4a7dc718479ab45d98d8ea488000000000000000011";
        let account_data = "f8440180a09dc8b927bc1f203931c70cc3850246046859c40e0044964753b28ff41285b75da0932cddc50793da935ccf915651ad67f6b746e9936fcc5614f0ff492563782c75";
        let key = "487bcece3757038b7fea6585ca2d0a3dacd72d84bf0c7b916f169cea0348681b";
        let proof = vec!["f90211a0a08073a06d519f053d34fbc01d7b52b5deff8bca1ecce1c6f5b64549215a1faca04354caea0b1a81283d78f0d2f876f8ef9232d3eff9c9266edf485d39a0ca9deaa01109339731fb837d1593f6fd40e9bcf9bf8b3869fc1f98c5e9fb91c19f6be941a0a699fab3b6374669ae93411b7f6f066b1a041a2f7456cac84ff29a93c6632da7a081c0eae435200744e1c85ff9918c7240790fd0d3f399cff2f90cde9d94e65fa4a04a04579f3a8b75d085a0f5a93858bf22ca3128232b69a3303e6342fea230f87fa0243bcb398a13ca1167b73593e895dd34ee0cebe89e9e553968155ab756b9b4caa022b916d96ea298160f55466ad1016b2ea60c9c60173cd193f82f0113e451280fa06f632d62fcffd685eee2357bd714772cea7cdc77f12454ad82a95f8de9059a16a0a16e576d1ab0bfbde3206d7efe42ac02b9d571421a69c91c698acf2afdc7e9e0a0392f3c5d59d3ed96044e32f152c76ce3eef74677d08df74fecbb163ca62da46ca0d84050065aa6746b033d129952fb8a3e1d92a24ceec830f44d0345e6bcb4e11fa098bfe8fd1931b9945e33ed558eab4764185294e5e8862df1709b6172ce52107aa036b54d7eb3e330033fc001bd65a07858eb98b3422bd30668da866256e3cc5381a04471a857d2967a0a1f37702d7fb19e983e46523affd393a87e6ee0b28e1dfe46a0c735f88df737eaeebb1156765174ab718dbea4e72f905767dd8cd38c19583eea80",
                                    "f90211a0c08abe73e8834debc4a228b4e0a5b8784a4163295ac6e991c057743a03911bf7a043770020cdf744075d88d216bc196b1ca01c2e67a98ed89535117f844e3f23efa04751dd21338bc05d356942b97ed568b2c3914af8cdb9e07ca608a94baa7695e7a0099b11c93b8021809fe5cc59fa5604623a0a8fe2abdbd48a559acb1b22a50e50a000fa6e28df7c9c8526b90f2494b645348bc52ccdb63765332623769e4015e967a08636c0d061574bf8d72bd229c0a6c4739f6e32d80557810096d28f9f877cfa49a0e7ca1390f44c7c0dc903b6ba88a4a4fde4d136531cb44766e3c6ded1273475dea00595c31ec3e7afe28019a5c6f4952efd16b67d94edaee043a4056a2782c31c5aa0f4bb8fd565bb24cc39b0157120afb40be99cde20c20d99363caebf955c5a13c6a0d8672a85e53d075497ff4da81422bfb10faec5c8c2d0044fccbc94954601c754a094cc70327bd4edbbff663f537d8b31ba8a903d6b22a4f47e020e01e07b1375b7a0fb3a0b5bda02815f4241d7a91ad1a428640c68a7753a5d692d5ade6d2fc9fb22a00dbe28cfae02f8b7ddc3ea544371b82df122997505672f4ca68e82b5431254cda0e434486a2f3f737717284c03014507ac7e9aeb5b33909e60aaead9cc729876daa0f490e0a91ae868d122649d0414fbf526df55191b428434d243e85bfeef6e2141a0ed079a0ef4612b5be78c7881f650bbfff67c291a418730f540636cd67803b2ba80",
                                    "f90211a099f584601ddfa456be8fb1bc11a9d04f89fca85d5a7b742751d1e632a112b0c5a03119421d72e57140841a5f019273c85a439a843da331185cdce9d2ca3541233aa06c63778935b724f11a966aa70e7fab290b5c742d4cdd67b6051d418304c9dd91a02069229873253405803d8e1d0d5d01911cc7671a8e22f8fa7e83d496ed6445bda08f4ea7df159e23d87f0e6a370c0b49dffb13b4de3557d36eae308ee70797f8dda044f9840dff4d78e22cf0c8cc6c77b51e8f8c0be913629e021066bc15c1da0e23a0666695b8555c0085aec60bd50f941b1ed1a06a64567886d12cc79810ada94e77a069593ccc40ed0a9a3eeaaf5ea77ec454ebd72ec1671046c50c6da8271043c79ca0455ed090dfc3ed5d4097591f5ef4117a4213bd785a02903d1b25ded965821e28a0155d59491e1bd7e76f03eb56f1052bc5af2f7f82358f6008228ba369985175dca08eaa3e82ba004f48941dea816449e49bbc121ad7ce7b90570468aad29274b4b8a041daac098787faaaea6de08d08f7fbac5adc72fe783daff123bf93d08dd3b4cda0bbc313e8353da043272aaa2b4dad484fd65ad832ade431cd9d4d6c567c8c0fb9a074c85dc357f3c01fad6fe1d5f801ac15c1cd0695d0cf19be226ebcb2ee69715da0a4b7e2287d825c0aaa494697012507e8ce86f2decea6fa0f18ed44a09e3d7778a09ea8b3cef67c5e5c6cf7b78b71171991c5a012e7441a8746569934cc35ec72e380",
                                    "f90211a088af0c98f29b354f5801982231cfaf32a21291de4a50cddb5919b7af4a3affc8a0646fd9cd70121f7aed81dcd3a3fa4032905b49ada1b269e1008dbc439ed8dd6ea09360adf6f6de594882463d6afb384a32bcbe075aab2ca772d32c25d877f015cea03f3fa2f3170926c970e1292dc31a5676af1aed81079c2f5c7934db9a412a04eea0df0c1e8fbc8bb7e9e86c7b87e915faae2c0c4e3fc15f786f3c815efba85f2c94a0c54057f44f64aacd0c20280168eb36c886b5ef2fdf91766990e7827425a6af90a06023a11acc770d7745556dc13a151ced8e06e69be2d8a2f2b77069af7472c43fa07556b4b2c3e648c5260055434e49551a4d58f4b0eb6e9199e3aa9850a8b9e85ea0a00895f7c1890ce6ab871e1936f544c16404344a0244fdf2a96d4b312bc1792ca04e617e01777906cff90a5497519ac519ea3303cc072f59da280750222581b30fa0aac76734716f149c1452cc6a24a7c6d6486126991dd0d9c8f409fa804544438ca0784105f279920dd248fd8ccd7f18855e2ce14d02d43a17339ef4fe85630c53a8a0f947985382b0d54e24536f2e08ee353994e298b928d946295853b98918e3c6f8a036b5d525ce50feef47ce0f7d1c95429fc607f21e2608242fcd22ab89e8dec82fa0a190c3e86d4b7806fc730f72f4a12a567e19a66b2d13281ac327adef4bb9a322a014fbde855de56cc7b2c8ceeb21bf728d9b16eb52f75519c7ef2e0d7438f9f52580",
                                    "f90211a096da0777dbb2f875bd357722a4387a78ae24efe13e04ed75f65b2c991247203fa0c0082d34071d1d65e712999126ac28e277b079d939821eaa755c4ef0fd2e5baaa03d98c1cea07206967cd60311f762514cefea1b945b65e35837fa91dadfd9adfba00930aa5c1b70190cd2231cc759fec0c863a2e11bc89b1685d17da64f6bdc5e72a010b3d58569454bcfe1e6c9fad76e7034972f2abb6a3081b3c6b057c7d3151e2ca0868e866d17747182e462be130ceb1b0b3b5011db9f10f3fc8a00743c50497eaaa0aff0dd0b6a09d0e5659b96333f74fd56545addb56451693c1daeb2dbd7fe4470a0dc8377293634ad6f039399e84e930e83ec270294221d00327b08c58ce9c1528ea049f69f18f5acee6f6b1a74a315eb74a51518e88065d645839f5831b371b23dfba016414a0cc05a4ff3a564f32519ab0f21a7d2c263efc1b1c54870db75ec53fb76a09458802b0e109265aacd42f071615e6dd83621b049caa8f05efd5f38b0559cd5a02d8273d7361b92d48df473707dea7efd87a4cfad1f60ffa7fb8cd0f352183dfda0aba4a49f637c164f4a7623b7286c6ff7f146704d4517b2c3c869d5a4db4b8122a0a274c42f4ccef6f20a413218137c6ec00ac7e3fa172f61a7c6487497fe427daba07b654da472355715776ca568289e057e2f0119930f77e557f238911ce4bd52d9a022ae048dd1bc27273ee6cb79991f8e0f34d17a4cba3b13d968cc49d36fe370ab80",
                                    "f90171a02a6e86561c33eacbb1826e9832a25f9f2841c281c9e6b6c18c95ce713dae6c868080a0807528ab397894421968b62bead3b9dd446bda7dc79a5b6ec5a29bd3f19a10c5a0072bce4e78f01cc370c9d92dd39bfcee6059d2e60a95135867991c59184d219980a0415df007b0977e95ba9b3d86b64bae14c02250b3da81f81bed47973f9e4a55b180a0e45736d96c006965b5cad5ec8008d31eb2c34e00c36f677b288701f76f43d627a055324754b7752c9149df27e03392c0598ec89f408040b15140a679f02e695017a04fc91448749dcab3e66cc8e45eb8d85a416fa3a33f8951128d17ca208bc3bb38a085a91d9af48d4f428da097b31c09b3f6b27d38212678a30ffd100364546a4d1ea0c60b5a89f1f89e97528a8b352ed55e5de2e7b963d73ba7de9e922c0ae964e816a048ff598a81a0114eb4afe71ef547cf6fecbb970310ef84049c9353d01c17103aa0e47f3c0d8c3b154c308fed503d87fc39546e1a7bbe143612fce1580110d5d6c08080",
                                    "f871808080808080a03f1587ebf71f19f47449b08f0960630ddbd60d045ea68ee7d89fb1c5682d215a8080808080a001210de038b44d1a57a695f46e2604e6646593958c64441b4fb679f4d16179d88080a05344081f911ad616b960a8f2841eb55f4936a97ec5dae614e726c8c0d51e0eff80",
                                    "f8669d3e3757038b7fea6585ca2d0a3dacd72d84bf0c7b916f169cea0348681bb846f8440180a09dc8b927bc1f203931c70cc3850246046859c40e0044964753b28ff41285b75da0932cddc50793da935ccf915651ad67f6b746e9936fcc5614f0ff492563782c75"
                                ];
        let processed_hash = "c687f93bfafb23a762293b4b190060938e6ac95cf15ddb66422865a925022b2f";
        let nonce = U128(1);
        let proof = generate_unlock_proof(header, account_data, key, proof, processed_hash, true);
        contract.unlock_callback(true, nonce, signer_account_id(), proof);
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
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "75"
            },
            "fee": {
                "token": "token_near",
                "amount": "75"
            },
             "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
            None,
        );
    }

    #[test]
    #[should_panic(expected = r#"Balance for token transfer: token_near299 not found"#)]
    fn test_lock_balance_not_found() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(Some(get_bridge_config_v1()));
        let balance: u128 = 100;

        contract.ft_on_transfer(signer_account_id(), U128(balance), "".to_string());
        contract.ft_on_transfer(signer_account_id(), U128(balance), "".to_string());

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 20;
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": "token_near299",
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "75"
            },
            "fee": {
                "token": "token_near",
                "amount": "75"
            },
             "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
            None,
        );
    }

    #[test]
    #[should_panic(expected = r#"Balance for token fee: token_near not found"#)]
    fn test_lock_fee_balance_not_found() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(Some(get_bridge_config_v1()));
        let balance: u128 = 100;

        let context = get_context_custom_signer(false, "token_near".to_string());
        testing_env!(context);
        contract.ft_on_transfer(signer_account_id(), U128(balance), "".to_string());

        let context = get_context_custom_signer(false, "token_near2".to_string());
        testing_env!(context);
        contract.ft_on_transfer(signer_account_id(), U128(balance), "".to_string());

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 20;
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": "token_near",
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "75"
            },
            "fee": {
                "token": "token_near299",
                "amount": "75"
            },
             "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
            None,
        );
    }

    #[test]
    #[should_panic(expected = r#"Transaction with id:"#)]
    fn test_unlock_transaction_not_found() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(Some(get_bridge_config_v1()));
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap(); // signer account
        let balance: u128 = 100;

        contract.ft_on_transfer(signer_account_id(), U128(balance), "".to_string());

        contract.ft_on_transfer(signer_account_id(), U128(balance), "".to_string());

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 20;
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": "token_near",
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "75"
            },
            "fee": {
                "token": "token_near",
                "amount": "75"
            },
             "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
            None,
        );

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(50, transfer_token_amount);

        let context = get_context_for_unlock(false);
        testing_env!(context);

        let header  = "f9021ba0695d799c7fbeda2651dd907991909e4ae68612851ce5398f2efc9506e69247cda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b64a30399f7f6b0c154c2e7af0a3ec7b0a5b131aa0eea9136af6ad8b65ad4c2184bbe6ab400f1ae214ed069d56d89639d7329d083ea063bbd1ab5c4e3922601b38d701e091e1ad3bc30a8e6e6a166728a6b5c9a61d31a0108126d36fb961af5e2d8359a6fced486e368965bbcba286205983dd06011aceb901000120011010a05000008a4800841200c0042918c020a44820008210109a02018c028d000000004001009a014c1085c000430019108410580008041204143226407a2001200470804449a0620802440121001124020cc07a040318018480a146110002528216204104220200806080086020c018a02000120020204818800000504604c1200000202100004003a188820624281c212102000901010d6051ec081002001a0000c8041010806460121600222104002188072024090001c60020088d2060c8ca500a1224161090040c82620c014060040608011048a1401010803004ba159d5800002802000300c241100296888004086a0030c015003b0212003004308380ffb58401c9c38083f281638463e31ac89f496c6c756d696e61746520446d6f63726174697a6520447374726962757465a086a600953aa2865ceb8c7a6348f388aaad93ca30c4a7dc718479ab45d98d8ea488000000000000000011";
        let account_data = "f8440180a09dc8b927bc1f203931c70cc3850246046859c40e0044964753b28ff41285b75da0932cddc50793da935ccf915651ad67f6b746e9936fcc5614f0ff492563782c75";
        let key = "487bcece3757038b7fea6585ca2d0a3dacd72d84bf0c7b916f169cea0348681b";
        let proof = vec!["f90211a0a08073a06d519f053d34fbc01d7b52b5deff8bca1ecce1c6f5b64549215a1faca04354caea0b1a81283d78f0d2f876f8ef9232d3eff9c9266edf485d39a0ca9deaa01109339731fb837d1593f6fd40e9bcf9bf8b3869fc1f98c5e9fb91c19f6be941a0a699fab3b6374669ae93411b7f6f066b1a041a2f7456cac84ff29a93c6632da7a081c0eae435200744e1c85ff9918c7240790fd0d3f399cff2f90cde9d94e65fa4a04a04579f3a8b75d085a0f5a93858bf22ca3128232b69a3303e6342fea230f87fa0243bcb398a13ca1167b73593e895dd34ee0cebe89e9e553968155ab756b9b4caa022b916d96ea298160f55466ad1016b2ea60c9c60173cd193f82f0113e451280fa06f632d62fcffd685eee2357bd714772cea7cdc77f12454ad82a95f8de9059a16a0a16e576d1ab0bfbde3206d7efe42ac02b9d571421a69c91c698acf2afdc7e9e0a0392f3c5d59d3ed96044e32f152c76ce3eef74677d08df74fecbb163ca62da46ca0d84050065aa6746b033d129952fb8a3e1d92a24ceec830f44d0345e6bcb4e11fa098bfe8fd1931b9945e33ed558eab4764185294e5e8862df1709b6172ce52107aa036b54d7eb3e330033fc001bd65a07858eb98b3422bd30668da866256e3cc5381a04471a857d2967a0a1f37702d7fb19e983e46523affd393a87e6ee0b28e1dfe46a0c735f88df737eaeebb1156765174ab718dbea4e72f905767dd8cd38c19583eea80",
                                    "f90211a0c08abe73e8834debc4a228b4e0a5b8784a4163295ac6e991c057743a03911bf7a043770020cdf744075d88d216bc196b1ca01c2e67a98ed89535117f844e3f23efa04751dd21338bc05d356942b97ed568b2c3914af8cdb9e07ca608a94baa7695e7a0099b11c93b8021809fe5cc59fa5604623a0a8fe2abdbd48a559acb1b22a50e50a000fa6e28df7c9c8526b90f2494b645348bc52ccdb63765332623769e4015e967a08636c0d061574bf8d72bd229c0a6c4739f6e32d80557810096d28f9f877cfa49a0e7ca1390f44c7c0dc903b6ba88a4a4fde4d136531cb44766e3c6ded1273475dea00595c31ec3e7afe28019a5c6f4952efd16b67d94edaee043a4056a2782c31c5aa0f4bb8fd565bb24cc39b0157120afb40be99cde20c20d99363caebf955c5a13c6a0d8672a85e53d075497ff4da81422bfb10faec5c8c2d0044fccbc94954601c754a094cc70327bd4edbbff663f537d8b31ba8a903d6b22a4f47e020e01e07b1375b7a0fb3a0b5bda02815f4241d7a91ad1a428640c68a7753a5d692d5ade6d2fc9fb22a00dbe28cfae02f8b7ddc3ea544371b82df122997505672f4ca68e82b5431254cda0e434486a2f3f737717284c03014507ac7e9aeb5b33909e60aaead9cc729876daa0f490e0a91ae868d122649d0414fbf526df55191b428434d243e85bfeef6e2141a0ed079a0ef4612b5be78c7881f650bbfff67c291a418730f540636cd67803b2ba80",
                                    "f90211a099f584601ddfa456be8fb1bc11a9d04f89fca85d5a7b742751d1e632a112b0c5a03119421d72e57140841a5f019273c85a439a843da331185cdce9d2ca3541233aa06c63778935b724f11a966aa70e7fab290b5c742d4cdd67b6051d418304c9dd91a02069229873253405803d8e1d0d5d01911cc7671a8e22f8fa7e83d496ed6445bda08f4ea7df159e23d87f0e6a370c0b49dffb13b4de3557d36eae308ee70797f8dda044f9840dff4d78e22cf0c8cc6c77b51e8f8c0be913629e021066bc15c1da0e23a0666695b8555c0085aec60bd50f941b1ed1a06a64567886d12cc79810ada94e77a069593ccc40ed0a9a3eeaaf5ea77ec454ebd72ec1671046c50c6da8271043c79ca0455ed090dfc3ed5d4097591f5ef4117a4213bd785a02903d1b25ded965821e28a0155d59491e1bd7e76f03eb56f1052bc5af2f7f82358f6008228ba369985175dca08eaa3e82ba004f48941dea816449e49bbc121ad7ce7b90570468aad29274b4b8a041daac098787faaaea6de08d08f7fbac5adc72fe783daff123bf93d08dd3b4cda0bbc313e8353da043272aaa2b4dad484fd65ad832ade431cd9d4d6c567c8c0fb9a074c85dc357f3c01fad6fe1d5f801ac15c1cd0695d0cf19be226ebcb2ee69715da0a4b7e2287d825c0aaa494697012507e8ce86f2decea6fa0f18ed44a09e3d7778a09ea8b3cef67c5e5c6cf7b78b71171991c5a012e7441a8746569934cc35ec72e380",
                                    "f90211a088af0c98f29b354f5801982231cfaf32a21291de4a50cddb5919b7af4a3affc8a0646fd9cd70121f7aed81dcd3a3fa4032905b49ada1b269e1008dbc439ed8dd6ea09360adf6f6de594882463d6afb384a32bcbe075aab2ca772d32c25d877f015cea03f3fa2f3170926c970e1292dc31a5676af1aed81079c2f5c7934db9a412a04eea0df0c1e8fbc8bb7e9e86c7b87e915faae2c0c4e3fc15f786f3c815efba85f2c94a0c54057f44f64aacd0c20280168eb36c886b5ef2fdf91766990e7827425a6af90a06023a11acc770d7745556dc13a151ced8e06e69be2d8a2f2b77069af7472c43fa07556b4b2c3e648c5260055434e49551a4d58f4b0eb6e9199e3aa9850a8b9e85ea0a00895f7c1890ce6ab871e1936f544c16404344a0244fdf2a96d4b312bc1792ca04e617e01777906cff90a5497519ac519ea3303cc072f59da280750222581b30fa0aac76734716f149c1452cc6a24a7c6d6486126991dd0d9c8f409fa804544438ca0784105f279920dd248fd8ccd7f18855e2ce14d02d43a17339ef4fe85630c53a8a0f947985382b0d54e24536f2e08ee353994e298b928d946295853b98918e3c6f8a036b5d525ce50feef47ce0f7d1c95429fc607f21e2608242fcd22ab89e8dec82fa0a190c3e86d4b7806fc730f72f4a12a567e19a66b2d13281ac327adef4bb9a322a014fbde855de56cc7b2c8ceeb21bf728d9b16eb52f75519c7ef2e0d7438f9f52580",
                                    "f90211a096da0777dbb2f875bd357722a4387a78ae24efe13e04ed75f65b2c991247203fa0c0082d34071d1d65e712999126ac28e277b079d939821eaa755c4ef0fd2e5baaa03d98c1cea07206967cd60311f762514cefea1b945b65e35837fa91dadfd9adfba00930aa5c1b70190cd2231cc759fec0c863a2e11bc89b1685d17da64f6bdc5e72a010b3d58569454bcfe1e6c9fad76e7034972f2abb6a3081b3c6b057c7d3151e2ca0868e866d17747182e462be130ceb1b0b3b5011db9f10f3fc8a00743c50497eaaa0aff0dd0b6a09d0e5659b96333f74fd56545addb56451693c1daeb2dbd7fe4470a0dc8377293634ad6f039399e84e930e83ec270294221d00327b08c58ce9c1528ea049f69f18f5acee6f6b1a74a315eb74a51518e88065d645839f5831b371b23dfba016414a0cc05a4ff3a564f32519ab0f21a7d2c263efc1b1c54870db75ec53fb76a09458802b0e109265aacd42f071615e6dd83621b049caa8f05efd5f38b0559cd5a02d8273d7361b92d48df473707dea7efd87a4cfad1f60ffa7fb8cd0f352183dfda0aba4a49f637c164f4a7623b7286c6ff7f146704d4517b2c3c869d5a4db4b8122a0a274c42f4ccef6f20a413218137c6ec00ac7e3fa172f61a7c6487497fe427daba07b654da472355715776ca568289e057e2f0119930f77e557f238911ce4bd52d9a022ae048dd1bc27273ee6cb79991f8e0f34d17a4cba3b13d968cc49d36fe370ab80",
                                    "f90171a02a6e86561c33eacbb1826e9832a25f9f2841c281c9e6b6c18c95ce713dae6c868080a0807528ab397894421968b62bead3b9dd446bda7dc79a5b6ec5a29bd3f19a10c5a0072bce4e78f01cc370c9d92dd39bfcee6059d2e60a95135867991c59184d219980a0415df007b0977e95ba9b3d86b64bae14c02250b3da81f81bed47973f9e4a55b180a0e45736d96c006965b5cad5ec8008d31eb2c34e00c36f677b288701f76f43d627a055324754b7752c9149df27e03392c0598ec89f408040b15140a679f02e695017a04fc91448749dcab3e66cc8e45eb8d85a416fa3a33f8951128d17ca208bc3bb38a085a91d9af48d4f428da097b31c09b3f6b27d38212678a30ffd100364546a4d1ea0c60b5a89f1f89e97528a8b352ed55e5de2e7b963d73ba7de9e922c0ae964e816a048ff598a81a0114eb4afe71ef547cf6fecbb970310ef84049c9353d01c17103aa0e47f3c0d8c3b154c308fed503d87fc39546e1a7bbe143612fce1580110d5d6c08080",
                                    "f871808080808080a03f1587ebf71f19f47449b08f0960630ddbd60d045ea68ee7d89fb1c5682d215a8080808080a001210de038b44d1a57a695f46e2604e6646593958c64441b4fb679f4d16179d88080a05344081f911ad616b960a8f2841eb55f4936a97ec5dae614e726c8c0d51e0eff80",
                                    "f8669d3e3757038b7fea6585ca2d0a3dacd72d84bf0c7b916f169cea0348681bb846f8440180a09dc8b927bc1f203931c70cc3850246046859c40e0044964753b28ff41285b75da0932cddc50793da935ccf915651ad67f6b746e9936fcc5614f0ff492563782c75"
                                ];
        let processed_hash = "9235d5bc6f69bc4e74d943ee6c335656308295d83097e391de62fffe955baabb";
        let proof = generate_unlock_proof(header, account_data, key, proof, processed_hash, true);

        contract.unlock_callback(true, U128(9), signer_account_id(), proof);
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);
    }

    #[test]
    #[should_panic(expected = "Permission denied for account:")]
    fn test_unlock_invalid_account() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(Some(get_bridge_config_v1()));
        test_unlock(&mut contract);
    }

    #[test]
    fn test_unrestricted_unlock() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(Some(get_bridge_config_v1()));
        contract.acl_grant_role(
            "UnrestrictedUnlock".to_string(),
            "dex_near".parse().unwrap(),
        );

        test_unlock(&mut contract);
    }

    fn test_unlock(contract: &mut FastBridge) {
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance: u128 = 100;

        contract.ft_on_transfer(signer_account_id(), U128(balance), "".to_string());
        let context = get_context_dex(false);
        testing_env!(context);
        contract.ft_on_transfer(signer_account_id(), U128(balance), "".to_string());
        let user_balance = contract.user_balances.get(&signer_account_id()).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();

        assert_eq!(100, transfer_token_amount);

        let context = get_context(false);
        testing_env!(context);
        contract.ft_on_transfer(signer_account_id(), U128(balance), "".to_string());
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();

        assert_eq!(200, transfer_token_amount);

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 20;
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": "token_near",
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "75"
            },
            "fee": {
                "token": "token_near",
                "amount": "75"
            },
             "recipient": "71c7656ec7ab88b098defb751b7401b5f6d8976f"
        });
        contract.init_transfer_callback(
            10,
            serde_json::from_value(msg).unwrap(),
            signer_account_id(),
            None,
        );

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(50, transfer_token_amount);

        let context = get_panic_context_for_unlock(false);
        testing_env!(context);

        let header  = "f9021ba0695d799c7fbeda2651dd907991909e4ae68612851ce5398f2efc9506e69247cda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b64a30399f7f6b0c154c2e7af0a3ec7b0a5b131aa0eea9136af6ad8b65ad4c2184bbe6ab400f1ae214ed069d56d89639d7329d083ea063bbd1ab5c4e3922601b38d701e091e1ad3bc30a8e6e6a166728a6b5c9a61d31a0108126d36fb961af5e2d8359a6fced486e368965bbcba286205983dd06011aceb901000120011010a05000008a4800841200c0042918c020a44820008210109a02018c028d000000004001009a014c1085c000430019108410580008041204143226407a2001200470804449a0620802440121001124020cc07a040318018480a146110002528216204104220200806080086020c018a02000120020204818800000504604c1200000202100004003a188820624281c212102000901010d6051ec081002001a0000c8041010806460121600222104002188072024090001c60020088d2060c8ca500a1224161090040c82620c014060040608011048a1401010803004ba159d5800002802000300c241100296888004086a0030c015003b0212003004308380ffb58401c9c38083f281638463e31ac89f496c6c756d696e61746520446d6f63726174697a6520447374726962757465a086a600953aa2865ceb8c7a6348f388aaad93ca30c4a7dc718479ab45d98d8ea488000000000000000011";
        let account_data = "f8440180a09dc8b927bc1f203931c70cc3850246046859c40e0044964753b28ff41285b75da0932cddc50793da935ccf915651ad67f6b746e9936fcc5614f0ff492563782c75";
        let key = "487bcece3757038b7fea6585ca2d0a3dacd72d84bf0c7b916f169cea0348681b";
        let proof = vec!["f90211a0a08073a06d519f053d34fbc01d7b52b5deff8bca1ecce1c6f5b64549215a1faca04354caea0b1a81283d78f0d2f876f8ef9232d3eff9c9266edf485d39a0ca9deaa01109339731fb837d1593f6fd40e9bcf9bf8b3869fc1f98c5e9fb91c19f6be941a0a699fab3b6374669ae93411b7f6f066b1a041a2f7456cac84ff29a93c6632da7a081c0eae435200744e1c85ff9918c7240790fd0d3f399cff2f90cde9d94e65fa4a04a04579f3a8b75d085a0f5a93858bf22ca3128232b69a3303e6342fea230f87fa0243bcb398a13ca1167b73593e895dd34ee0cebe89e9e553968155ab756b9b4caa022b916d96ea298160f55466ad1016b2ea60c9c60173cd193f82f0113e451280fa06f632d62fcffd685eee2357bd714772cea7cdc77f12454ad82a95f8de9059a16a0a16e576d1ab0bfbde3206d7efe42ac02b9d571421a69c91c698acf2afdc7e9e0a0392f3c5d59d3ed96044e32f152c76ce3eef74677d08df74fecbb163ca62da46ca0d84050065aa6746b033d129952fb8a3e1d92a24ceec830f44d0345e6bcb4e11fa098bfe8fd1931b9945e33ed558eab4764185294e5e8862df1709b6172ce52107aa036b54d7eb3e330033fc001bd65a07858eb98b3422bd30668da866256e3cc5381a04471a857d2967a0a1f37702d7fb19e983e46523affd393a87e6ee0b28e1dfe46a0c735f88df737eaeebb1156765174ab718dbea4e72f905767dd8cd38c19583eea80",
                                    "f90211a0c08abe73e8834debc4a228b4e0a5b8784a4163295ac6e991c057743a03911bf7a043770020cdf744075d88d216bc196b1ca01c2e67a98ed89535117f844e3f23efa04751dd21338bc05d356942b97ed568b2c3914af8cdb9e07ca608a94baa7695e7a0099b11c93b8021809fe5cc59fa5604623a0a8fe2abdbd48a559acb1b22a50e50a000fa6e28df7c9c8526b90f2494b645348bc52ccdb63765332623769e4015e967a08636c0d061574bf8d72bd229c0a6c4739f6e32d80557810096d28f9f877cfa49a0e7ca1390f44c7c0dc903b6ba88a4a4fde4d136531cb44766e3c6ded1273475dea00595c31ec3e7afe28019a5c6f4952efd16b67d94edaee043a4056a2782c31c5aa0f4bb8fd565bb24cc39b0157120afb40be99cde20c20d99363caebf955c5a13c6a0d8672a85e53d075497ff4da81422bfb10faec5c8c2d0044fccbc94954601c754a094cc70327bd4edbbff663f537d8b31ba8a903d6b22a4f47e020e01e07b1375b7a0fb3a0b5bda02815f4241d7a91ad1a428640c68a7753a5d692d5ade6d2fc9fb22a00dbe28cfae02f8b7ddc3ea544371b82df122997505672f4ca68e82b5431254cda0e434486a2f3f737717284c03014507ac7e9aeb5b33909e60aaead9cc729876daa0f490e0a91ae868d122649d0414fbf526df55191b428434d243e85bfeef6e2141a0ed079a0ef4612b5be78c7881f650bbfff67c291a418730f540636cd67803b2ba80",
                                    "f90211a099f584601ddfa456be8fb1bc11a9d04f89fca85d5a7b742751d1e632a112b0c5a03119421d72e57140841a5f019273c85a439a843da331185cdce9d2ca3541233aa06c63778935b724f11a966aa70e7fab290b5c742d4cdd67b6051d418304c9dd91a02069229873253405803d8e1d0d5d01911cc7671a8e22f8fa7e83d496ed6445bda08f4ea7df159e23d87f0e6a370c0b49dffb13b4de3557d36eae308ee70797f8dda044f9840dff4d78e22cf0c8cc6c77b51e8f8c0be913629e021066bc15c1da0e23a0666695b8555c0085aec60bd50f941b1ed1a06a64567886d12cc79810ada94e77a069593ccc40ed0a9a3eeaaf5ea77ec454ebd72ec1671046c50c6da8271043c79ca0455ed090dfc3ed5d4097591f5ef4117a4213bd785a02903d1b25ded965821e28a0155d59491e1bd7e76f03eb56f1052bc5af2f7f82358f6008228ba369985175dca08eaa3e82ba004f48941dea816449e49bbc121ad7ce7b90570468aad29274b4b8a041daac098787faaaea6de08d08f7fbac5adc72fe783daff123bf93d08dd3b4cda0bbc313e8353da043272aaa2b4dad484fd65ad832ade431cd9d4d6c567c8c0fb9a074c85dc357f3c01fad6fe1d5f801ac15c1cd0695d0cf19be226ebcb2ee69715da0a4b7e2287d825c0aaa494697012507e8ce86f2decea6fa0f18ed44a09e3d7778a09ea8b3cef67c5e5c6cf7b78b71171991c5a012e7441a8746569934cc35ec72e380",
                                    "f90211a088af0c98f29b354f5801982231cfaf32a21291de4a50cddb5919b7af4a3affc8a0646fd9cd70121f7aed81dcd3a3fa4032905b49ada1b269e1008dbc439ed8dd6ea09360adf6f6de594882463d6afb384a32bcbe075aab2ca772d32c25d877f015cea03f3fa2f3170926c970e1292dc31a5676af1aed81079c2f5c7934db9a412a04eea0df0c1e8fbc8bb7e9e86c7b87e915faae2c0c4e3fc15f786f3c815efba85f2c94a0c54057f44f64aacd0c20280168eb36c886b5ef2fdf91766990e7827425a6af90a06023a11acc770d7745556dc13a151ced8e06e69be2d8a2f2b77069af7472c43fa07556b4b2c3e648c5260055434e49551a4d58f4b0eb6e9199e3aa9850a8b9e85ea0a00895f7c1890ce6ab871e1936f544c16404344a0244fdf2a96d4b312bc1792ca04e617e01777906cff90a5497519ac519ea3303cc072f59da280750222581b30fa0aac76734716f149c1452cc6a24a7c6d6486126991dd0d9c8f409fa804544438ca0784105f279920dd248fd8ccd7f18855e2ce14d02d43a17339ef4fe85630c53a8a0f947985382b0d54e24536f2e08ee353994e298b928d946295853b98918e3c6f8a036b5d525ce50feef47ce0f7d1c95429fc607f21e2608242fcd22ab89e8dec82fa0a190c3e86d4b7806fc730f72f4a12a567e19a66b2d13281ac327adef4bb9a322a014fbde855de56cc7b2c8ceeb21bf728d9b16eb52f75519c7ef2e0d7438f9f52580",
                                    "f90211a096da0777dbb2f875bd357722a4387a78ae24efe13e04ed75f65b2c991247203fa0c0082d34071d1d65e712999126ac28e277b079d939821eaa755c4ef0fd2e5baaa03d98c1cea07206967cd60311f762514cefea1b945b65e35837fa91dadfd9adfba00930aa5c1b70190cd2231cc759fec0c863a2e11bc89b1685d17da64f6bdc5e72a010b3d58569454bcfe1e6c9fad76e7034972f2abb6a3081b3c6b057c7d3151e2ca0868e866d17747182e462be130ceb1b0b3b5011db9f10f3fc8a00743c50497eaaa0aff0dd0b6a09d0e5659b96333f74fd56545addb56451693c1daeb2dbd7fe4470a0dc8377293634ad6f039399e84e930e83ec270294221d00327b08c58ce9c1528ea049f69f18f5acee6f6b1a74a315eb74a51518e88065d645839f5831b371b23dfba016414a0cc05a4ff3a564f32519ab0f21a7d2c263efc1b1c54870db75ec53fb76a09458802b0e109265aacd42f071615e6dd83621b049caa8f05efd5f38b0559cd5a02d8273d7361b92d48df473707dea7efd87a4cfad1f60ffa7fb8cd0f352183dfda0aba4a49f637c164f4a7623b7286c6ff7f146704d4517b2c3c869d5a4db4b8122a0a274c42f4ccef6f20a413218137c6ec00ac7e3fa172f61a7c6487497fe427daba07b654da472355715776ca568289e057e2f0119930f77e557f238911ce4bd52d9a022ae048dd1bc27273ee6cb79991f8e0f34d17a4cba3b13d968cc49d36fe370ab80",
                                    "f90171a02a6e86561c33eacbb1826e9832a25f9f2841c281c9e6b6c18c95ce713dae6c868080a0807528ab397894421968b62bead3b9dd446bda7dc79a5b6ec5a29bd3f19a10c5a0072bce4e78f01cc370c9d92dd39bfcee6059d2e60a95135867991c59184d219980a0415df007b0977e95ba9b3d86b64bae14c02250b3da81f81bed47973f9e4a55b180a0e45736d96c006965b5cad5ec8008d31eb2c34e00c36f677b288701f76f43d627a055324754b7752c9149df27e03392c0598ec89f408040b15140a679f02e695017a04fc91448749dcab3e66cc8e45eb8d85a416fa3a33f8951128d17ca208bc3bb38a085a91d9af48d4f428da097b31c09b3f6b27d38212678a30ffd100364546a4d1ea0c60b5a89f1f89e97528a8b352ed55e5de2e7b963d73ba7de9e922c0ae964e816a048ff598a81a0114eb4afe71ef547cf6fecbb970310ef84049c9353d01c17103aa0e47f3c0d8c3b154c308fed503d87fc39546e1a7bbe143612fce1580110d5d6c08080",
                                    "f871808080808080a03f1587ebf71f19f47449b08f0960630ddbd60d045ea68ee7d89fb1c5682d215a8080808080a001210de038b44d1a57a695f46e2604e6646593958c64441b4fb679f4d16179d88080a05344081f911ad616b960a8f2841eb55f4936a97ec5dae614e726c8c0d51e0eff80",
                                    "f8669d3e3757038b7fea6585ca2d0a3dacd72d84bf0c7b916f169cea0348681bb846f8440180a09dc8b927bc1f203931c70cc3850246046859c40e0044964753b28ff41285b75da0932cddc50793da935ccf915651ad67f6b746e9936fcc5614f0ff492563782c75"
                                ];
        let processed_hash = "c687f93bfafb23a762293b4b190060938e6ac95cf15ddb66422865a925022b2f";
        let proof = generate_unlock_proof(header, account_data, key, proof, processed_hash, true);

        contract.unlock_callback(true, U128(1), signer_account_id(), proof);
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
        contract.ft_on_transfer(transfer_token.clone(), U128(amount), "".to_string());
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
        contract.ft_on_transfer(transfer_token.clone(), U128(amount), "".to_string());

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
        contract.acl_grant_role("ConfigManager".to_string(), "token_near".parse().unwrap());
        contract.set_enear_address(invalid_address);
    }

    #[test]
    fn test_set_enear_address() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let valid_address: String = "42".repeat(20);
        let valid_eth_address: Vec<u8> = eth_encode_packed::hex::decode(valid_address.clone()).unwrap();
        contract.acl_grant_role("ConfigManager".to_string(), "token_near".parse().unwrap());
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
        contract.acl_grant_role("ConfigManager".to_string(), "token_near".parse().unwrap());
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
                    contract.increase_balance(&user, &token, &10);
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
        contract.set_token_whitelist_mode(token_account.clone(), WhitelistMode::Blocked);
        set_env!(predecessor_account_id: token_account, signer_account_id: sender_account.clone());
        contract.ft_on_transfer(sender_account, U128(1_000_000), ethereum_address_from_id(0));
    }

    #[test]
    #[should_panic(expected = "isn't whitelisted for the account")]
    fn test_account_not_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = get_bridge_contract(None);

        let token_account = accounts(1);
        let sender_account = accounts(2);
        contract.set_token_whitelist_mode(accounts(1), WhitelistMode::CheckAccountAndToken);
        set_env!(predecessor_account_id: token_account, signer_account_id: sender_account.clone());
        contract.ft_on_transfer(sender_account, U128(1_000_000), "".to_string());
    }

    #[test]
    #[should_panic(expected = "is not whitelisted")]
    fn test_token_not_in_whitelist() {
        set_env!(predecessor_account_id: accounts(0));
        let mut contract = get_bridge_contract(None);

        let token_account = accounts(1);
        let sender_account = accounts(2);
        set_env!(predecessor_account_id: token_account, signer_account_id: sender_account.clone());
        contract.ft_on_transfer(sender_account, U128(1_000_000), "".to_string());
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
        contract.ft_on_transfer(sender_account, U128(1_000_000), "".to_string());
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
        contract.ft_on_transfer(sender_account.clone(), U128(1_000_000), "".to_string());

        set_env!(predecessor_account_id: accounts(0));
        contract.remove_token_from_account_whitelist(
            Some(token_account.clone()),
            sender_account.clone(),
        );

        set_env!(predecessor_account_id: token_account.clone(), signer_account_id: sender_account.clone());
        contract.ft_on_transfer(sender_account.clone(), U128(1_000_000), "".to_string());
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
            contract.ft_on_transfer(sender_account, U128(1_000_000), "".to_string());
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
                contract.ft_on_transfer(sender_account, U128(1_000_000), "".to_string());
            }
        }
    }
}
