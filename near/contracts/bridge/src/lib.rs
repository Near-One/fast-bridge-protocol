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
    fn verify_storage_proof(
        &self,
        #[serializer(borsh)] header_data: Vec<u8>,
        #[serializer(borsh)] account_proof: Vec<Vec<u8>>, // account proof
        #[serializer(borsh)] contract_address: Vec<u8>,   // eth address
        #[serializer(borsh)] account_state: Vec<u8>,      // rlp encoded account state
        #[serializer(borsh)] storage_key_hash: Vec<u8>,   // keccak256 of storage key
        #[serializer(borsh)] storage_proof: Vec<Vec<u8>>, // storage proof
        #[serializer(borsh)] value: Vec<u8>,              // storage value
        #[serializer(borsh)] min_header_height: Option<u64>,
        #[serializer(borsh)] max_header_height: Option<u64>,
        #[serializer(borsh)] skip_bridge_call: bool,
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
    fn unlock_callback(
        &mut self,
        #[callback]
        #[serializer(borsh)]
        verification_result: bool,
        #[serializer(borsh)] nonce: U128,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] transfer_data: TransferMessage,
        #[serializer(borsh)] recipient_id: AccountId,
    );
    fn init_transfer_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] sender_id: AccountId,
        #[serializer(borsh)] update_balance: Option<UpdateBalance>,
    ) -> PromiseOrValue<U128>;
}

#[derive(
    Default, BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize, PartialEq,
)]
pub struct UnlockProof {
    header_data: Vec<u8>,
    account_proof: Vec<Vec<u8>>,
    account_data: Vec<u8>,
    storage_proof: Vec<Vec<u8>>,
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
    pub fn unlock(&self, nonce: U128, proof: near_sdk::json_types::Base64VecU8) -> Promise {
        let proof = UnlockProof::try_from_slice(&proof.0)
            .unwrap_or_else(|_| env::panic_str("Invalid borsh format of the `UnlockProof`"));

        let (recipient_id, transfer_data) = self
            .get_pending_transfer(nonce.0.to_string())
            .unwrap_or_else(|| near_sdk::env::panic_str("Transfer not found"));

        let storage_key_hash = utils::get_eth_storage_key_hash(
            transfer_data.transfer.token_eth,
            transfer_data.recipient,
            eth_types::U256(nonce.0.into()),
            eth_types::U256(transfer_data.transfer.amount.0.into()),
        );

        ext_prover::ext(self.prover_account.clone())
            .with_static_gas(utils::tera_gas(50))
            .with_attached_deposit(utils::NO_DEPOSIT)
            .verify_storage_proof(
                proof.header_data,
                proof.account_proof,
                self.eth_bridge_contract.to_vec(),
                proof.account_data,
                storage_key_hash,
                proof.storage_proof,
                vec![],
                transfer_data.valid_till_block_height,
                None,
                false,
            )
            .then(
                ext_self::ext(current_account_id())
                    .with_static_gas(utils::tera_gas(50))
                    .with_attached_deposit(utils::NO_DEPOSIT)
                    .unlock_callback(
                        nonce,
                        env::predecessor_account_id(),
                        transfer_data,
                        recipient_id,
                    ),
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
        #[serializer(borsh)] transfer_data: TransferMessage,
        #[serializer(borsh)] recipient_id: AccountId,
    ) {
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
            format!("Verification failed for unlock proof")
        );

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
        self.remove_transfer(&nonce.0.to_string(), &transfer_data);

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

        let nonce_str = proof.nonce.to_string();

        let transfer = self
            .pending_transfers
            .get(&nonce_str)
            .unwrap_or_else(|| panic!("Transaction with id: {} not found", &nonce_str));
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
        self.remove_transfer(&nonce_str, &transfer_data);

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
        let account_pending = (sender_id, transfer_message);
        self.pending_transfers
            .insert(&self.nonce.to_string(), &account_pending);
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
    pub fn withdraw(&mut self, token_id: AccountId, amount: U128) -> Promise {
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
            )
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
    pub fn set_eth_bridge_contract_address(&mut self, address: String) {
        self.eth_bridge_contract = fast_bridge_common::get_eth_address(address);
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
        let nonce = U128(1);
        let nonce_str = nonce.0.to_string();
        let (recipient_id, transfer_data) = contract
            .pending_transfers
            .get(&nonce_str)
            .unwrap_or_else(|| panic!("Transaction with id: {} not found", &nonce_str.to_string()));
        contract.unlock_callback(
            true,
            nonce,
            signer_account_id(),
            transfer_data,
            recipient_id,
        );
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(200, transfer_token_amount);
    }

    #[test]
    fn test_unlock_for_valid_proof() {
        let context = get_context(false);
        testing_env!(context);
        let mut contract = get_bridge_contract(None);
        let transfer_token: AccountId = AccountId::try_from("token_near".to_string()).unwrap();
        let transfer_account: AccountId = AccountId::try_from("bob_near".to_string()).unwrap();
        let balance = U128(200);

        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());
        contract.ft_on_transfer(transfer_account.clone(), balance, "".to_string());

        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(400, transfer_token_amount);

        let current_timestamp = block_timestamp() + contract.lock_duration.lock_time_min + 1;
        let msg = json!({
            "valid_till": current_timestamp,
            "transfer": {
                "token_near": "token_near",
                "token_eth": "71c7656ec7ab88b098defb751b7401b5f6d8976f",
                "amount": "200"
            },
            "fee": {
                "token": "token_near",
                "amount": "200"
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

        let context = get_context_for_unlock(false);
        testing_env!(context);

        let nonce = U128(1);
        let nonce_str = nonce.0.to_string();
        let (recipient_id, transfer_data) = contract
            .pending_transfers
            .get(&nonce_str)
            .unwrap_or_else(|| panic!("Transaction with id: {} not found", &nonce_str.to_string()));

        contract.unlock_callback(
            true,
            nonce,
            signer_account_id(),
            transfer_data,
            recipient_id,
        );
        let user_balance = contract.user_balances.get(&transfer_account).unwrap();
        let transfer_token_amount = user_balance.get(&transfer_token).unwrap();
        assert_eq!(400, transfer_token_amount); //user get the all 400 tokens back after successfull valid proof submition
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
    #[should_panic(expected = r#"The fee token does not match the transfer token"#)]
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
    #[should_panic(expected = r#"The fee token does not match the transfer token"#)]
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

        let nonce = U128(9);
        let nonce_str = nonce.0.to_string();
        let (recipient_id, transfer_data) = contract
            .pending_transfers
            .get(&nonce_str)
            .unwrap_or_else(|| panic!("Transaction with id: {} not found", &nonce_str.to_string()));

        contract.unlock_callback(
            true,
            nonce,
            signer_account_id(),
            transfer_data,
            recipient_id,
        );
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

        let nonce = U128(1);
        let nonce_str = nonce.0.to_string();
        let (recipient_id, transfer_data) = contract
            .pending_transfers
            .get(&nonce_str)
            .unwrap_or_else(|| panic!("Transfer with nonce: {} not found", &nonce_str));

        contract.unlock_callback(
            true,
            nonce,
            signer_account_id(),
            transfer_data,
            recipient_id,
        );
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
        let valid_eth_address: Vec<u8> = hex::decode(valid_address.clone()).unwrap();
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
