#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
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
    env, ext_contract, is_promise_success, near_bindgen, require, AccountId,
    BorshStorageKey, Duration, PanicOnDefault, PromiseOrValue,
};
use parse_duration::parse;
use whitelist::WhitelistMode;
pub use crate::ft::*;
mod ft {
    use crate::*;
    use near_contract_standards::fungible_token::receiver::FungibleTokenReceiver;
    use near_sdk::{base64, AccountId};
    impl FastBridgeExt {
        pub fn ft_on_transfer(
            self,
            sender_id: AccountId,
            amount: U128,
            msg: String,
        ) -> near_sdk::Promise {
            let __args = {
                #[serde(crate = "near_sdk::serde")]
                struct Input<'nearinput> {
                    sender_id: &'nearinput AccountId,
                    amount: &'nearinput U128,
                    msg: &'nearinput String,
                }
                #[doc(hidden)]
                #[allow(
                    non_upper_case_globals,
                    unused_attributes,
                    unused_qualifications
                )]
                const _: () = {
                    use near_sdk::serde as _serde;
                    #[automatically_derived]
                    impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                        fn serialize<__S>(
                            &self,
                            __serializer: __S,
                        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                        where
                            __S: near_sdk::serde::Serializer,
                        {
                            let mut __serde_state = match _serde::Serializer::serialize_struct(
                                __serializer,
                                "Input",
                                false as usize + 1 + 1 + 1,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "sender_id",
                                &self.sender_id,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "amount",
                                &self.amount,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "msg",
                                &self.msg,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::ser::SerializeStruct::end(__serde_state)
                        }
                    }
                };
                let __args = Input {
                    sender_id: &sender_id,
                    amount: &amount,
                    msg: &msg,
                };
                near_sdk::serde_json::to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using JSON.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "ft_on_transfer".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
    }
    impl FungibleTokenReceiver for FastBridge {
        fn ft_on_transfer(
            &mut self,
            sender_id: AccountId,
            amount: U128,
            msg: String,
        ) -> PromiseOrValue<U128> {
            let mut __check_paused = true;
            let __except_roles: Vec<&str> = ::alloc::vec::Vec::new();
            let __except_roles: Vec<String> = __except_roles
                .iter()
                .map(|&x| x.into())
                .collect();
            let may_bypass = self
                .acl_has_any_role(
                    __except_roles,
                    ::near_sdk::env::predecessor_account_id(),
                );
            if may_bypass {
                __check_paused = false;
            }
            if __check_paused {
                if true {
                    let msg: &str = &"Pausable: Method is paused";
                    if !!self.pa_is_paused("ft_on_transfer".to_string()) {
                        ::core::panicking::panic_display(&msg)
                    }
                } else if !!self.pa_is_paused("ft_on_transfer".to_string()) {
                    ::near_sdk::env::panic_str(&"Pausable: Method is paused")
                }
            }
            if true {
                let msg: &str = &"Sender is not the same as the signer";
                if !(sender_id == env::signer_account_id()) {
                    ::core::panicking::panic_display(&msg)
                }
            } else if !(sender_id == env::signer_account_id()) {
                ::near_sdk::env::panic_str(&"Sender is not the same as the signer")
            }
            let token_account_id = env::predecessor_account_id();
            self.check_whitelist_token_and_account(&token_account_id, &sender_id);
            if !msg.is_empty() {
                let decoded_base64 = base64::decode(&msg)
                    .unwrap_or_else(|_| env::panic_str("Invalid base64 message"));
                let transfer_message = TransferMessage::try_from_slice(&decoded_base64)
                    .unwrap_or_else(|_| {
                        env::panic_str("Invalid borsh format of the `TransferMessage`")
                    });
                let update_balance = UpdateBalance {
                    sender_id: sender_id.clone(),
                    token: token_account_id,
                    amount,
                };
                self.init_transfer_internal(
                        transfer_message,
                        sender_id,
                        Some(update_balance),
                    )
                    .into()
            } else {
                self.increase_balance(&sender_id, &token_account_id, &amount.0);
                Event::FastBridgeDepositEvent {
                    sender_id,
                    token: token_account_id,
                    amount,
                }
                    .emit();
                PromiseOrValue::Value(U128::from(0))
            }
        }
    }
    #[cfg(target_arch = "wasm32")]
    #[no_mangle]
    pub extern "C" fn ft_on_transfer() {
        near_sdk::env::setup_panic_hook();
        if near_sdk::env::attached_deposit() != 0 {
            near_sdk::env::panic_str("Method ft_on_transfer doesn't accept deposit");
        }
        #[serde(crate = "near_sdk::serde")]
        struct Input {
            sender_id: AccountId,
            amount: U128,
            msg: String,
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            use near_sdk::serde as _serde;
            #[automatically_derived]
            impl<'de> near_sdk::serde::Deserialize<'de> for Input {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> near_sdk::serde::__private::Result<Self, __D::Error>
                where
                    __D: near_sdk::serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    enum __Field {
                        __field0,
                        __field1,
                        __field2,
                        __ignore,
                    }
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                2u64 => _serde::__private::Ok(__Field::__field2),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "sender_id" => _serde::__private::Ok(__Field::__field0),
                                "amount" => _serde::__private::Ok(__Field::__field1),
                                "msg" => _serde::__private::Ok(__Field::__field2),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"sender_id" => _serde::__private::Ok(__Field::__field0),
                                b"amount" => _serde::__private::Ok(__Field::__field1),
                                b"msg" => _serde::__private::Ok(__Field::__field2),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Input>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Input;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Input",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match match _serde::de::SeqAccess::next_element::<
                                AccountId,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Input with 3 elements",
                                        ),
                                    );
                                }
                            };
                            let __field1 = match match _serde::de::SeqAccess::next_element::<
                                U128,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Input with 3 elements",
                                        ),
                                    );
                                }
                            };
                            let __field2 = match match _serde::de::SeqAccess::next_element::<
                                String,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            2usize,
                                            &"struct Input with 3 elements",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(Input {
                                sender_id: __field0,
                                amount: __field1,
                                msg: __field2,
                            })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<AccountId> = _serde::__private::None;
                            let mut __field1: _serde::__private::Option<U128> = _serde::__private::None;
                            let mut __field2: _serde::__private::Option<String> = _serde::__private::None;
                            while let _serde::__private::Some(__key)
                                = match _serde::de::MapAccess::next_key::<
                                    __Field,
                                >(&mut __map) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                } {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "sender_id",
                                                ),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                AccountId,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    __Field::__field1 => {
                                        if _serde::__private::Option::is_some(&__field1) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("amount"),
                                            );
                                        }
                                        __field1 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                U128,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    __Field::__field2 => {
                                        if _serde::__private::Option::is_some(&__field2) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("msg"),
                                            );
                                        }
                                        __field2 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                String,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    _ => {
                                        let _ = match _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        };
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("sender_id") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            let __field1 = match __field1 {
                                _serde::__private::Some(__field1) => __field1,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("amount") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            let __field2 = match __field2 {
                                _serde::__private::Some(__field2) => __field2,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("msg") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            _serde::__private::Ok(Input {
                                sender_id: __field0,
                                amount: __field1,
                                msg: __field2,
                            })
                        }
                    }
                    const FIELDS: &'static [&'static str] = &[
                        "sender_id",
                        "amount",
                        "msg",
                    ];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "Input",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Input>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        let Input { sender_id, amount, msg }: Input = near_sdk::serde_json::from_slice(
                &near_sdk::env::input()
                    .expect("Expected input since method has arguments."),
            )
            .expect("Failed to deserialize input from JSON.");
        let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
        let result = contract.ft_on_transfer(sender_id, amount, msg);
        let result = near_sdk::serde_json::to_vec(&result)
            .expect("Failed to serialize the return value using JSON.");
        near_sdk::env::value_return(&result);
        near_sdk::env::state_write(&contract);
    }
}
mod lp_relayer {
    use eth_types::{LogEntry, H256};
    use ethabi::{Event, EventParam, Hash, ParamType, RawLog};
    use fast_bridge_common::*;
    use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
    use near_sdk::near_bindgen;
    type EthEventParams = Vec<(String, ParamType, bool)>;
    const EVENT_NAME: &str = "TransferTokens";
    pub struct EthTransferEvent {
        pub eth_bridge_contract: EthAddress,
        pub nonce: u128,
        pub relayer: EthAddress,
        pub token: EthAddress,
        pub recipient: EthAddress,
        pub amount: u128,
        pub unlock_recipient: String,
        pub transfer_id: H256,
    }
    impl borsh::de::BorshDeserialize for EthTransferEvent
    where
        EthAddress: borsh::BorshDeserialize,
        u128: borsh::BorshDeserialize,
        EthAddress: borsh::BorshDeserialize,
        EthAddress: borsh::BorshDeserialize,
        EthAddress: borsh::BorshDeserialize,
        u128: borsh::BorshDeserialize,
        String: borsh::BorshDeserialize,
        H256: borsh::BorshDeserialize,
    {
        fn deserialize(
            buf: &mut &[u8],
        ) -> ::core::result::Result<Self, borsh::maybestd::io::Error> {
            Ok(Self {
                eth_bridge_contract: borsh::BorshDeserialize::deserialize(buf)?,
                nonce: borsh::BorshDeserialize::deserialize(buf)?,
                relayer: borsh::BorshDeserialize::deserialize(buf)?,
                token: borsh::BorshDeserialize::deserialize(buf)?,
                recipient: borsh::BorshDeserialize::deserialize(buf)?,
                amount: borsh::BorshDeserialize::deserialize(buf)?,
                unlock_recipient: borsh::BorshDeserialize::deserialize(buf)?,
                transfer_id: borsh::BorshDeserialize::deserialize(buf)?,
            })
        }
    }
    impl borsh::ser::BorshSerialize for EthTransferEvent
    where
        EthAddress: borsh::ser::BorshSerialize,
        u128: borsh::ser::BorshSerialize,
        EthAddress: borsh::ser::BorshSerialize,
        EthAddress: borsh::ser::BorshSerialize,
        EthAddress: borsh::ser::BorshSerialize,
        u128: borsh::ser::BorshSerialize,
        String: borsh::ser::BorshSerialize,
        H256: borsh::ser::BorshSerialize,
    {
        fn serialize<W: borsh::maybestd::io::Write>(
            &self,
            writer: &mut W,
        ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
            borsh::BorshSerialize::serialize(&self.eth_bridge_contract, writer)?;
            borsh::BorshSerialize::serialize(&self.nonce, writer)?;
            borsh::BorshSerialize::serialize(&self.relayer, writer)?;
            borsh::BorshSerialize::serialize(&self.token, writer)?;
            borsh::BorshSerialize::serialize(&self.recipient, writer)?;
            borsh::BorshSerialize::serialize(&self.amount, writer)?;
            borsh::BorshSerialize::serialize(&self.unlock_recipient, writer)?;
            borsh::BorshSerialize::serialize(&self.transfer_id, writer)?;
            Ok(())
        }
    }
    #[must_use]
    pub struct EthTransferEventExt {
        pub(crate) account_id: near_sdk::AccountId,
        pub(crate) deposit: near_sdk::Balance,
        pub(crate) static_gas: near_sdk::Gas,
        pub(crate) gas_weight: near_sdk::GasWeight,
    }
    impl EthTransferEventExt {
        pub fn with_attached_deposit(mut self, amount: near_sdk::Balance) -> Self {
            self.deposit = amount;
            self
        }
        pub fn with_static_gas(mut self, static_gas: near_sdk::Gas) -> Self {
            self.static_gas = static_gas;
            self
        }
        pub fn with_unused_gas_weight(mut self, gas_weight: u64) -> Self {
            self.gas_weight = near_sdk::GasWeight(gas_weight);
            self
        }
    }
    impl EthTransferEvent {
        /// API for calling this contract's functions in a subsequent execution.
        pub fn ext(account_id: near_sdk::AccountId) -> EthTransferEventExt {
            EthTransferEventExt {
                account_id,
                deposit: 0,
                static_gas: near_sdk::Gas(0),
                gas_weight: near_sdk::GasWeight::default(),
            }
        }
    }
    impl EthTransferEvent {
        pub fn event_params() -> EthEventParams {
            <[_]>::into_vec(
                #[rustc_box]
                ::alloc::boxed::Box::new([
                    ("nonce".to_string(), ParamType::Uint(256), true),
                    ("relayer".to_string(), ParamType::Address, false),
                    ("token".to_string(), ParamType::Address, false),
                    ("recipient".to_string(), ParamType::Address, false),
                    ("amount".to_string(), ParamType::Uint(256), false),
                    ("unlock_recipient".to_string(), ParamType::String, false),
                    ("transfer_id".to_string(), ParamType::FixedBytes(32), true),
                ]),
            )
        }
        pub fn parse(proof: Proof) -> Self {
            let data = proof.log_entry_data;
            let params = EthTransferEvent::event_params();
            let event = Event {
                name: EVENT_NAME.to_string(),
                inputs: params
                    .into_iter()
                    .map(|(name, kind, indexed)| EventParam { name, kind, indexed })
                    .collect(),
                anonymous: false,
            };
            let log_entry: LogEntry = rlp::decode(&data).expect("Invalid RLP");
            let locker_address = (log_entry.address.0).0;
            let topics = log_entry
                .topics
                .iter()
                .map(|h| Hash::from(&((h.0).0)))
                .collect();
            let raw_log = RawLog {
                topics,
                data: log_entry.data,
            };
            let log = event.parse_log(raw_log).expect("Failed to parse event log");
            let nonce = log.params[0].value.clone().to_uint().unwrap().as_u128();
            let relayer = log.params[1].value.clone().to_address().unwrap().0;
            let token = log.params[2].value.clone().to_address().unwrap().0;
            let recipient = log.params[3].value.clone().to_address().unwrap().0;
            let amount = log.params[4].value.clone().to_uint().unwrap().as_u128();
            let unlock_recipient = log.params[5].value.clone().to_string().unwrap();
            let transfer_id: H256 = log
                .params[6]
                .value
                .clone()
                .to_fixed_bytes()
                .unwrap()
                .try_into()
                .unwrap();
            Self {
                eth_bridge_contract: locker_address,
                nonce,
                relayer,
                token,
                recipient,
                amount,
                unlock_recipient,
                transfer_id,
            }
        }
    }
}
mod utils {
    use near_sdk::Gas;
    pub const TGAS: Gas = near_sdk::Gas::ONE_TERA;
    pub const NO_DEPOSIT: u128 = 0;
    pub fn tera_gas(gas: u64) -> Gas {
        TGAS * gas
    }
    pub fn get_transaction_id(id: u128) -> String {
        id.to_string()
    }
    pub fn is_valid_eth_address(address: String) -> bool {
        if hex::decode(address.clone()).is_err() {
            return false;
        }
        hex::decode(address).unwrap().len() == 20
    }
}
mod whitelist {
    use near_plugins::access_control_any;
    use near_sdk::serde::{Deserialize, Serialize};
    use near_sdk::{env, AccountId};
    use crate::*;
    #[serde(crate = "near_sdk::serde")]
    pub enum WhitelistMode {
        Blocked,
        CheckToken,
        CheckAccountAndToken,
    }
    impl borsh::de::BorshDeserialize for WhitelistMode {
        fn deserialize(
            buf: &mut &[u8],
        ) -> core::result::Result<Self, borsh::maybestd::io::Error> {
            let variant_idx: u8 = borsh::BorshDeserialize::deserialize(buf)?;
            let return_value = match variant_idx {
                0u8 => WhitelistMode::Blocked,
                1u8 => WhitelistMode::CheckToken,
                2u8 => WhitelistMode::CheckAccountAndToken,
                _ => {
                    let msg = {
                        let res = ::alloc::fmt::format(
                            ::core::fmt::Arguments::new_v1(
                                &["Unexpected variant index: "],
                                &[::core::fmt::ArgumentV1::new_debug(&variant_idx)],
                            ),
                        );
                        res
                    };
                    return Err(
                        borsh::maybestd::io::Error::new(
                            borsh::maybestd::io::ErrorKind::InvalidInput,
                            msg,
                        ),
                    );
                }
            };
            Ok(return_value)
        }
    }
    impl borsh::ser::BorshSerialize for WhitelistMode {
        fn serialize<W: borsh::maybestd::io::Write>(
            &self,
            writer: &mut W,
        ) -> core::result::Result<(), borsh::maybestd::io::Error> {
            let variant_idx: u8 = match self {
                WhitelistMode::Blocked => 0u8,
                WhitelistMode::CheckToken => 1u8,
                WhitelistMode::CheckAccountAndToken => 2u8,
            };
            writer.write_all(&variant_idx.to_le_bytes())?;
            match self {
                WhitelistMode::Blocked => {}
                WhitelistMode::CheckToken => {}
                WhitelistMode::CheckAccountAndToken => {}
            }
            Ok(())
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for WhitelistMode {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __field2,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "variant identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            2u64 => _serde::__private::Ok(__Field::__field2),
                            _ => {
                                _serde::__private::Err(
                                    _serde::de::Error::invalid_value(
                                        _serde::de::Unexpected::Unsigned(__value),
                                        &"variant index 0 <= i < 3",
                                    ),
                                )
                            }
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "Blocked" => _serde::__private::Ok(__Field::__field0),
                            "CheckToken" => _serde::__private::Ok(__Field::__field1),
                            "CheckAccountAndToken" => {
                                _serde::__private::Ok(__Field::__field2)
                            }
                            _ => {
                                _serde::__private::Err(
                                    _serde::de::Error::unknown_variant(__value, VARIANTS),
                                )
                            }
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"Blocked" => _serde::__private::Ok(__Field::__field0),
                            b"CheckToken" => _serde::__private::Ok(__Field::__field1),
                            b"CheckAccountAndToken" => {
                                _serde::__private::Ok(__Field::__field2)
                            }
                            _ => {
                                let __value = &_serde::__private::from_utf8_lossy(__value);
                                _serde::__private::Err(
                                    _serde::de::Error::unknown_variant(__value, VARIANTS),
                                )
                            }
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<WhitelistMode>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = WhitelistMode;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "enum WhitelistMode",
                        )
                    }
                    fn visit_enum<__A>(
                        self,
                        __data: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::EnumAccess<'de>,
                    {
                        match match _serde::de::EnumAccess::variant(__data) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            (__Field::__field0, __variant) => {
                                match _serde::de::VariantAccess::unit_variant(__variant) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                };
                                _serde::__private::Ok(WhitelistMode::Blocked)
                            }
                            (__Field::__field1, __variant) => {
                                match _serde::de::VariantAccess::unit_variant(__variant) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                };
                                _serde::__private::Ok(WhitelistMode::CheckToken)
                            }
                            (__Field::__field2, __variant) => {
                                match _serde::de::VariantAccess::unit_variant(__variant) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                };
                                _serde::__private::Ok(WhitelistMode::CheckAccountAndToken)
                            }
                        }
                    }
                }
                const VARIANTS: &'static [&'static str] = &[
                    "Blocked",
                    "CheckToken",
                    "CheckAccountAndToken",
                ];
                _serde::Deserializer::deserialize_enum(
                    __deserializer,
                    "WhitelistMode",
                    VARIANTS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<WhitelistMode>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl near_sdk::serde::Serialize for WhitelistMode {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: near_sdk::serde::Serializer,
            {
                match *self {
                    WhitelistMode::Blocked => {
                        _serde::Serializer::serialize_unit_variant(
                            __serializer,
                            "WhitelistMode",
                            0u32,
                            "Blocked",
                        )
                    }
                    WhitelistMode::CheckToken => {
                        _serde::Serializer::serialize_unit_variant(
                            __serializer,
                            "WhitelistMode",
                            1u32,
                            "CheckToken",
                        )
                    }
                    WhitelistMode::CheckAccountAndToken => {
                        _serde::Serializer::serialize_unit_variant(
                            __serializer,
                            "WhitelistMode",
                            2u32,
                            "CheckAccountAndToken",
                        )
                    }
                }
            }
        }
    };
    #[automatically_derived]
    impl ::core::fmt::Debug for WhitelistMode {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                WhitelistMode::Blocked => ::core::fmt::Formatter::write_str(f, "Blocked"),
                WhitelistMode::CheckToken => {
                    ::core::fmt::Formatter::write_str(f, "CheckToken")
                }
                WhitelistMode::CheckAccountAndToken => {
                    ::core::fmt::Formatter::write_str(f, "CheckAccountAndToken")
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for WhitelistMode {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for WhitelistMode {
        #[inline]
        fn eq(&self, other: &WhitelistMode) -> bool {
            let __self_tag = ::core::intrinsics::discriminant_value(self);
            let __arg1_tag = ::core::intrinsics::discriminant_value(other);
            __self_tag == __arg1_tag
        }
    }
    fn get_token_account_key(token: Option<&AccountId>, account: &AccountId) -> String {
        if let Some(token) = token {
            {
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &["", ":"],
                        &[
                            ::core::fmt::ArgumentV1::new_display(&token),
                            ::core::fmt::ArgumentV1::new_display(&account),
                        ],
                    ),
                );
                res
            }
        } else {
            account.to_string()
        }
    }
    impl FastBridgeExt {
        pub fn set_token_whitelist_mode(
            self,
            token: AccountId,
            mode: WhitelistMode,
        ) -> near_sdk::Promise {
            let __args = {
                #[serde(crate = "near_sdk::serde")]
                struct Input<'nearinput> {
                    token: &'nearinput AccountId,
                    mode: &'nearinput WhitelistMode,
                }
                #[doc(hidden)]
                #[allow(
                    non_upper_case_globals,
                    unused_attributes,
                    unused_qualifications
                )]
                const _: () = {
                    use near_sdk::serde as _serde;
                    #[automatically_derived]
                    impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                        fn serialize<__S>(
                            &self,
                            __serializer: __S,
                        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                        where
                            __S: near_sdk::serde::Serializer,
                        {
                            let mut __serde_state = match _serde::Serializer::serialize_struct(
                                __serializer,
                                "Input",
                                false as usize + 1 + 1,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "token",
                                &self.token,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "mode",
                                &self.mode,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::ser::SerializeStruct::end(__serde_state)
                        }
                    }
                };
                let __args = Input {
                    token: &token,
                    mode: &mode,
                };
                near_sdk::serde_json::to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using JSON.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "set_token_whitelist_mode".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
        pub fn add_token_to_account_whitelist(
            self,
            token: Option<AccountId>,
            account: AccountId,
        ) -> near_sdk::Promise {
            let __args = {
                #[serde(crate = "near_sdk::serde")]
                struct Input<'nearinput> {
                    token: &'nearinput Option<AccountId>,
                    account: &'nearinput AccountId,
                }
                #[doc(hidden)]
                #[allow(
                    non_upper_case_globals,
                    unused_attributes,
                    unused_qualifications
                )]
                const _: () = {
                    use near_sdk::serde as _serde;
                    #[automatically_derived]
                    impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                        fn serialize<__S>(
                            &self,
                            __serializer: __S,
                        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                        where
                            __S: near_sdk::serde::Serializer,
                        {
                            let mut __serde_state = match _serde::Serializer::serialize_struct(
                                __serializer,
                                "Input",
                                false as usize + 1 + 1,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "token",
                                &self.token,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "account",
                                &self.account,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::ser::SerializeStruct::end(__serde_state)
                        }
                    }
                };
                let __args = Input {
                    token: &token,
                    account: &account,
                };
                near_sdk::serde_json::to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using JSON.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "add_token_to_account_whitelist".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
        pub fn remove_token_from_account_whitelist(
            self,
            token: Option<AccountId>,
            account: AccountId,
        ) -> near_sdk::Promise {
            let __args = {
                #[serde(crate = "near_sdk::serde")]
                struct Input<'nearinput> {
                    token: &'nearinput Option<AccountId>,
                    account: &'nearinput AccountId,
                }
                #[doc(hidden)]
                #[allow(
                    non_upper_case_globals,
                    unused_attributes,
                    unused_qualifications
                )]
                const _: () = {
                    use near_sdk::serde as _serde;
                    #[automatically_derived]
                    impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                        fn serialize<__S>(
                            &self,
                            __serializer: __S,
                        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                        where
                            __S: near_sdk::serde::Serializer,
                        {
                            let mut __serde_state = match _serde::Serializer::serialize_struct(
                                __serializer,
                                "Input",
                                false as usize + 1 + 1,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "token",
                                &self.token,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "account",
                                &self.account,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::ser::SerializeStruct::end(__serde_state)
                        }
                    }
                };
                let __args = Input {
                    token: &token,
                    account: &account,
                };
                near_sdk::serde_json::to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using JSON.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "remove_token_from_account_whitelist".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
        pub fn check_whitelist_token_and_account(
            self,
            token: &AccountId,
            account: &AccountId,
        ) -> near_sdk::Promise {
            let __args = {
                #[serde(crate = "near_sdk::serde")]
                struct Input<'nearinput> {
                    token: &'nearinput AccountId,
                    account: &'nearinput AccountId,
                }
                #[doc(hidden)]
                #[allow(
                    non_upper_case_globals,
                    unused_attributes,
                    unused_qualifications
                )]
                const _: () = {
                    use near_sdk::serde as _serde;
                    #[automatically_derived]
                    impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                        fn serialize<__S>(
                            &self,
                            __serializer: __S,
                        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                        where
                            __S: near_sdk::serde::Serializer,
                        {
                            let mut __serde_state = match _serde::Serializer::serialize_struct(
                                __serializer,
                                "Input",
                                false as usize + 1 + 1,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "token",
                                &self.token,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "account",
                                &self.account,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::ser::SerializeStruct::end(__serde_state)
                        }
                    }
                };
                let __args = Input {
                    token: &token,
                    account: &account,
                };
                near_sdk::serde_json::to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using JSON.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "check_whitelist_token_and_account".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
        pub fn set_whitelist_mode_enabled(self, enabled: bool) -> near_sdk::Promise {
            let __args = {
                #[serde(crate = "near_sdk::serde")]
                struct Input<'nearinput> {
                    enabled: &'nearinput bool,
                }
                #[doc(hidden)]
                #[allow(
                    non_upper_case_globals,
                    unused_attributes,
                    unused_qualifications
                )]
                const _: () = {
                    use near_sdk::serde as _serde;
                    #[automatically_derived]
                    impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                        fn serialize<__S>(
                            &self,
                            __serializer: __S,
                        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                        where
                            __S: near_sdk::serde::Serializer,
                        {
                            let mut __serde_state = match _serde::Serializer::serialize_struct(
                                __serializer,
                                "Input",
                                false as usize + 1,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "enabled",
                                &self.enabled,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::ser::SerializeStruct::end(__serde_state)
                        }
                    }
                };
                let __args = Input { enabled: &enabled };
                near_sdk::serde_json::to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using JSON.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "set_whitelist_mode_enabled".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
        pub fn get_whitelist_tokens(self) -> near_sdk::Promise {
            let __args = ::alloc::vec::Vec::new();
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "get_whitelist_tokens".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
        pub fn get_whitelist_accounts(self) -> near_sdk::Promise {
            let __args = ::alloc::vec::Vec::new();
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "get_whitelist_accounts".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
    }
    impl FastBridge {
        pub fn set_token_whitelist_mode(
            &mut self,
            token: AccountId,
            mode: WhitelistMode,
        ) {
            let __acl_any_roles: Vec<&str> = <[_]>::into_vec(
                #[rustc_box]
                ::alloc::boxed::Box::new([Role::WhitelistManager.into()]),
            );
            let __acl_any_roles_ser: Vec<String> = __acl_any_roles
                .iter()
                .map(|&role| role.into())
                .collect();
            let __acl_any_account_id = ::near_sdk::env::predecessor_account_id();
            if !self.acl_has_any_role(__acl_any_roles_ser, __acl_any_account_id) {
                let message = {
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &[
                                "Insufficient permissions for method ",
                                " restricted by access control. Requires one of these roles: ",
                            ],
                            &[
                                ::core::fmt::ArgumentV1::new_display(
                                    &"set_token_whitelist_mode",
                                ),
                                ::core::fmt::ArgumentV1::new_debug(&__acl_any_roles),
                            ],
                        ),
                    );
                    res
                };
                near_sdk::env::panic_str(&message);
            }
            self.whitelist_tokens.insert(&token, &mode);
        }
        pub fn add_token_to_account_whitelist(
            &mut self,
            token: Option<AccountId>,
            account: AccountId,
        ) {
            let __acl_any_roles: Vec<&str> = <[_]>::into_vec(
                #[rustc_box]
                ::alloc::boxed::Box::new([Role::WhitelistManager.into()]),
            );
            let __acl_any_roles_ser: Vec<String> = __acl_any_roles
                .iter()
                .map(|&role| role.into())
                .collect();
            let __acl_any_account_id = ::near_sdk::env::predecessor_account_id();
            if !self.acl_has_any_role(__acl_any_roles_ser, __acl_any_account_id) {
                let message = {
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &[
                                "Insufficient permissions for method ",
                                " restricted by access control. Requires one of these roles: ",
                            ],
                            &[
                                ::core::fmt::ArgumentV1::new_display(
                                    &"add_token_to_account_whitelist",
                                ),
                                ::core::fmt::ArgumentV1::new_debug(&__acl_any_roles),
                            ],
                        ),
                    );
                    res
                };
                near_sdk::env::panic_str(&message);
            }
            if let Some(token) = &token {
                if !self.whitelist_tokens.get(token).is_some() {
                    ::core::panicking::panic_fmt(
                        ::core::fmt::Arguments::new_v1(
                            &["The whitelisted token mode is not set"],
                            &[],
                        ),
                    )
                }
            }
            self.whitelist_accounts
                .insert(&get_token_account_key(token.as_ref(), &account));
        }
        pub fn remove_token_from_account_whitelist(
            &mut self,
            token: Option<AccountId>,
            account: AccountId,
        ) -> bool {
            let __acl_any_roles: Vec<&str> = <[_]>::into_vec(
                #[rustc_box]
                ::alloc::boxed::Box::new([Role::WhitelistManager.into()]),
            );
            let __acl_any_roles_ser: Vec<String> = __acl_any_roles
                .iter()
                .map(|&role| role.into())
                .collect();
            let __acl_any_account_id = ::near_sdk::env::predecessor_account_id();
            if !self.acl_has_any_role(__acl_any_roles_ser, __acl_any_account_id) {
                let message = {
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &[
                                "Insufficient permissions for method ",
                                " restricted by access control. Requires one of these roles: ",
                            ],
                            &[
                                ::core::fmt::ArgumentV1::new_display(
                                    &"remove_token_from_account_whitelist",
                                ),
                                ::core::fmt::ArgumentV1::new_debug(&__acl_any_roles),
                            ],
                        ),
                    );
                    res
                };
                near_sdk::env::panic_str(&message);
            }
            self.whitelist_accounts
                .remove(&get_token_account_key(token.as_ref(), &account))
        }
        pub fn check_whitelist_token_and_account(
            &self,
            token: &AccountId,
            account: &AccountId,
        ) {
            if !self.is_whitelist_mode_enabled {
                return;
            }
            let token_whitelist_mode = self
                .whitelist_tokens
                .get(token)
                .unwrap_or_else(|| {
                    env::panic_str(
                        {
                            let res = ::alloc::fmt::format(
                                ::core::fmt::Arguments::new_v1(
                                    &["The token `", "` is not whitelisted"],
                                    &[::core::fmt::ArgumentV1::new_display(&token)],
                                ),
                            );
                            res
                        }
                            .as_str(),
                    )
                });
            match token_whitelist_mode {
                WhitelistMode::CheckAccountAndToken => {
                    let token_account_key = get_token_account_key(Some(token), account);
                    if true {
                        let msg: &str = &{
                            let res = ::alloc::fmt::format(
                                ::core::fmt::Arguments::new_v1(
                                    &[
                                        "The token `",
                                        "` isn\'t whitelisted for the account `",
                                        "`",
                                    ],
                                    &[
                                        ::core::fmt::ArgumentV1::new_display(&token),
                                        ::core::fmt::ArgumentV1::new_display(&account),
                                    ],
                                ),
                            );
                            res
                        };
                        if !(self.whitelist_accounts.contains(&token_account_key)
                            || self.whitelist_accounts.contains(&account.to_string()))
                        {
                            ::core::panicking::panic_display(&msg)
                        }
                    } else if !(self.whitelist_accounts.contains(&token_account_key)
                        || self.whitelist_accounts.contains(&account.to_string()))
                    {
                        ::near_sdk::env::panic_str(
                            &{
                                let res = ::alloc::fmt::format(
                                    ::core::fmt::Arguments::new_v1(
                                        &[
                                            "The token `",
                                            "` isn\'t whitelisted for the account `",
                                            "`",
                                        ],
                                        &[
                                            ::core::fmt::ArgumentV1::new_display(&token),
                                            ::core::fmt::ArgumentV1::new_display(&account),
                                        ],
                                    ),
                                );
                                res
                            },
                        )
                    }
                }
                WhitelistMode::CheckToken => {}
                WhitelistMode::Blocked => {
                    env::panic_str(
                        {
                            let res = ::alloc::fmt::format(
                                ::core::fmt::Arguments::new_v1(
                                    &["The token `", "` is blocked"],
                                    &[::core::fmt::ArgumentV1::new_display(&token)],
                                ),
                            );
                            res
                        }
                            .as_str(),
                    )
                }
            }
        }
        pub fn set_whitelist_mode_enabled(&mut self, enabled: bool) {
            let __acl_any_roles: Vec<&str> = <[_]>::into_vec(
                #[rustc_box]
                ::alloc::boxed::Box::new([Role::WhitelistManager.into()]),
            );
            let __acl_any_roles_ser: Vec<String> = __acl_any_roles
                .iter()
                .map(|&role| role.into())
                .collect();
            let __acl_any_account_id = ::near_sdk::env::predecessor_account_id();
            if !self.acl_has_any_role(__acl_any_roles_ser, __acl_any_account_id) {
                let message = {
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &[
                                "Insufficient permissions for method ",
                                " restricted by access control. Requires one of these roles: ",
                            ],
                            &[
                                ::core::fmt::ArgumentV1::new_display(
                                    &"set_whitelist_mode_enabled",
                                ),
                                ::core::fmt::ArgumentV1::new_debug(&__acl_any_roles),
                            ],
                        ),
                    );
                    res
                };
                near_sdk::env::panic_str(&message);
            }
            self.is_whitelist_mode_enabled = enabled;
        }
        pub fn get_whitelist_tokens(&self) -> Vec<(AccountId, WhitelistMode)> {
            self.whitelist_tokens.iter().collect::<Vec<_>>()
        }
        pub fn get_whitelist_accounts(&self) -> Vec<String> {
            self.whitelist_accounts.iter().collect::<Vec<_>>()
        }
    }
    #[cfg(target_arch = "wasm32")]
    #[no_mangle]
    pub extern "C" fn set_token_whitelist_mode() {
        near_sdk::env::setup_panic_hook();
        if near_sdk::env::attached_deposit() != 0 {
            near_sdk::env::panic_str(
                "Method set_token_whitelist_mode doesn't accept deposit",
            );
        }
        #[serde(crate = "near_sdk::serde")]
        struct Input {
            token: AccountId,
            mode: WhitelistMode,
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            use near_sdk::serde as _serde;
            #[automatically_derived]
            impl<'de> near_sdk::serde::Deserialize<'de> for Input {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> near_sdk::serde::__private::Result<Self, __D::Error>
                where
                    __D: near_sdk::serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    enum __Field {
                        __field0,
                        __field1,
                        __ignore,
                    }
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "token" => _serde::__private::Ok(__Field::__field0),
                                "mode" => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"token" => _serde::__private::Ok(__Field::__field0),
                                b"mode" => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Input>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Input;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Input",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match match _serde::de::SeqAccess::next_element::<
                                AccountId,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Input with 2 elements",
                                        ),
                                    );
                                }
                            };
                            let __field1 = match match _serde::de::SeqAccess::next_element::<
                                WhitelistMode,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Input with 2 elements",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(Input {
                                token: __field0,
                                mode: __field1,
                            })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<AccountId> = _serde::__private::None;
                            let mut __field1: _serde::__private::Option<WhitelistMode> = _serde::__private::None;
                            while let _serde::__private::Some(__key)
                                = match _serde::de::MapAccess::next_key::<
                                    __Field,
                                >(&mut __map) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                } {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("token"),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                AccountId,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    __Field::__field1 => {
                                        if _serde::__private::Option::is_some(&__field1) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("mode"),
                                            );
                                        }
                                        __field1 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                WhitelistMode,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    _ => {
                                        let _ = match _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        };
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("token") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            let __field1 = match __field1 {
                                _serde::__private::Some(__field1) => __field1,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("mode") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            _serde::__private::Ok(Input {
                                token: __field0,
                                mode: __field1,
                            })
                        }
                    }
                    const FIELDS: &'static [&'static str] = &["token", "mode"];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "Input",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Input>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        let Input { token, mode }: Input = near_sdk::serde_json::from_slice(
                &near_sdk::env::input()
                    .expect("Expected input since method has arguments."),
            )
            .expect("Failed to deserialize input from JSON.");
        let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
        contract.set_token_whitelist_mode(token, mode);
        near_sdk::env::state_write(&contract);
    }
    #[cfg(target_arch = "wasm32")]
    #[no_mangle]
    pub extern "C" fn add_token_to_account_whitelist() {
        near_sdk::env::setup_panic_hook();
        if near_sdk::env::attached_deposit() != 0 {
            near_sdk::env::panic_str(
                "Method add_token_to_account_whitelist doesn't accept deposit",
            );
        }
        #[serde(crate = "near_sdk::serde")]
        struct Input {
            token: Option<AccountId>,
            account: AccountId,
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            use near_sdk::serde as _serde;
            #[automatically_derived]
            impl<'de> near_sdk::serde::Deserialize<'de> for Input {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> near_sdk::serde::__private::Result<Self, __D::Error>
                where
                    __D: near_sdk::serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    enum __Field {
                        __field0,
                        __field1,
                        __ignore,
                    }
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "token" => _serde::__private::Ok(__Field::__field0),
                                "account" => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"token" => _serde::__private::Ok(__Field::__field0),
                                b"account" => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Input>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Input;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Input",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match match _serde::de::SeqAccess::next_element::<
                                Option<AccountId>,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Input with 2 elements",
                                        ),
                                    );
                                }
                            };
                            let __field1 = match match _serde::de::SeqAccess::next_element::<
                                AccountId,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Input with 2 elements",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(Input {
                                token: __field0,
                                account: __field1,
                            })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<
                                Option<AccountId>,
                            > = _serde::__private::None;
                            let mut __field1: _serde::__private::Option<AccountId> = _serde::__private::None;
                            while let _serde::__private::Some(__key)
                                = match _serde::de::MapAccess::next_key::<
                                    __Field,
                                >(&mut __map) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                } {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("token"),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                Option<AccountId>,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    __Field::__field1 => {
                                        if _serde::__private::Option::is_some(&__field1) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "account",
                                                ),
                                            );
                                        }
                                        __field1 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                AccountId,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    _ => {
                                        let _ = match _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        };
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("token") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            let __field1 = match __field1 {
                                _serde::__private::Some(__field1) => __field1,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("account") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            _serde::__private::Ok(Input {
                                token: __field0,
                                account: __field1,
                            })
                        }
                    }
                    const FIELDS: &'static [&'static str] = &["token", "account"];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "Input",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Input>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        let Input { token, account }: Input = near_sdk::serde_json::from_slice(
                &near_sdk::env::input()
                    .expect("Expected input since method has arguments."),
            )
            .expect("Failed to deserialize input from JSON.");
        let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
        contract.add_token_to_account_whitelist(token, account);
        near_sdk::env::state_write(&contract);
    }
    #[cfg(target_arch = "wasm32")]
    #[no_mangle]
    pub extern "C" fn remove_token_from_account_whitelist() {
        near_sdk::env::setup_panic_hook();
        if near_sdk::env::attached_deposit() != 0 {
            near_sdk::env::panic_str(
                "Method remove_token_from_account_whitelist doesn't accept deposit",
            );
        }
        #[serde(crate = "near_sdk::serde")]
        struct Input {
            token: Option<AccountId>,
            account: AccountId,
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            use near_sdk::serde as _serde;
            #[automatically_derived]
            impl<'de> near_sdk::serde::Deserialize<'de> for Input {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> near_sdk::serde::__private::Result<Self, __D::Error>
                where
                    __D: near_sdk::serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    enum __Field {
                        __field0,
                        __field1,
                        __ignore,
                    }
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "token" => _serde::__private::Ok(__Field::__field0),
                                "account" => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"token" => _serde::__private::Ok(__Field::__field0),
                                b"account" => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Input>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Input;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Input",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match match _serde::de::SeqAccess::next_element::<
                                Option<AccountId>,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Input with 2 elements",
                                        ),
                                    );
                                }
                            };
                            let __field1 = match match _serde::de::SeqAccess::next_element::<
                                AccountId,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Input with 2 elements",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(Input {
                                token: __field0,
                                account: __field1,
                            })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<
                                Option<AccountId>,
                            > = _serde::__private::None;
                            let mut __field1: _serde::__private::Option<AccountId> = _serde::__private::None;
                            while let _serde::__private::Some(__key)
                                = match _serde::de::MapAccess::next_key::<
                                    __Field,
                                >(&mut __map) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                } {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("token"),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                Option<AccountId>,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    __Field::__field1 => {
                                        if _serde::__private::Option::is_some(&__field1) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "account",
                                                ),
                                            );
                                        }
                                        __field1 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                AccountId,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    _ => {
                                        let _ = match _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        };
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("token") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            let __field1 = match __field1 {
                                _serde::__private::Some(__field1) => __field1,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("account") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            _serde::__private::Ok(Input {
                                token: __field0,
                                account: __field1,
                            })
                        }
                    }
                    const FIELDS: &'static [&'static str] = &["token", "account"];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "Input",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Input>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        let Input { token, account }: Input = near_sdk::serde_json::from_slice(
                &near_sdk::env::input()
                    .expect("Expected input since method has arguments."),
            )
            .expect("Failed to deserialize input from JSON.");
        let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
        let result = contract.remove_token_from_account_whitelist(token, account);
        let result = near_sdk::serde_json::to_vec(&result)
            .expect("Failed to serialize the return value using JSON.");
        near_sdk::env::value_return(&result);
        near_sdk::env::state_write(&contract);
    }
    #[cfg(target_arch = "wasm32")]
    #[no_mangle]
    pub extern "C" fn check_whitelist_token_and_account() {
        near_sdk::env::setup_panic_hook();
        #[serde(crate = "near_sdk::serde")]
        struct Input {
            token: AccountId,
            account: AccountId,
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            use near_sdk::serde as _serde;
            #[automatically_derived]
            impl<'de> near_sdk::serde::Deserialize<'de> for Input {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> near_sdk::serde::__private::Result<Self, __D::Error>
                where
                    __D: near_sdk::serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    enum __Field {
                        __field0,
                        __field1,
                        __ignore,
                    }
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                1u64 => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "token" => _serde::__private::Ok(__Field::__field0),
                                "account" => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"token" => _serde::__private::Ok(__Field::__field0),
                                b"account" => _serde::__private::Ok(__Field::__field1),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Input>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Input;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Input",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match match _serde::de::SeqAccess::next_element::<
                                AccountId,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Input with 2 elements",
                                        ),
                                    );
                                }
                            };
                            let __field1 = match match _serde::de::SeqAccess::next_element::<
                                AccountId,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            1usize,
                                            &"struct Input with 2 elements",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(Input {
                                token: __field0,
                                account: __field1,
                            })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<AccountId> = _serde::__private::None;
                            let mut __field1: _serde::__private::Option<AccountId> = _serde::__private::None;
                            while let _serde::__private::Some(__key)
                                = match _serde::de::MapAccess::next_key::<
                                    __Field,
                                >(&mut __map) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                } {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("token"),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                AccountId,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    __Field::__field1 => {
                                        if _serde::__private::Option::is_some(&__field1) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "account",
                                                ),
                                            );
                                        }
                                        __field1 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                AccountId,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    _ => {
                                        let _ = match _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        };
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("token") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            let __field1 = match __field1 {
                                _serde::__private::Some(__field1) => __field1,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("account") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            _serde::__private::Ok(Input {
                                token: __field0,
                                account: __field1,
                            })
                        }
                    }
                    const FIELDS: &'static [&'static str] = &["token", "account"];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "Input",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Input>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        let Input { token, account }: Input = near_sdk::serde_json::from_slice(
                &near_sdk::env::input()
                    .expect("Expected input since method has arguments."),
            )
            .expect("Failed to deserialize input from JSON.");
        let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
        contract.check_whitelist_token_and_account(&token, &account);
    }
    #[cfg(target_arch = "wasm32")]
    #[no_mangle]
    pub extern "C" fn set_whitelist_mode_enabled() {
        near_sdk::env::setup_panic_hook();
        if near_sdk::env::attached_deposit() != 0 {
            near_sdk::env::panic_str(
                "Method set_whitelist_mode_enabled doesn't accept deposit",
            );
        }
        #[serde(crate = "near_sdk::serde")]
        struct Input {
            enabled: bool,
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            use near_sdk::serde as _serde;
            #[automatically_derived]
            impl<'de> near_sdk::serde::Deserialize<'de> for Input {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> near_sdk::serde::__private::Result<Self, __D::Error>
                where
                    __D: near_sdk::serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    enum __Field {
                        __field0,
                        __ignore,
                    }
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "enabled" => _serde::__private::Ok(__Field::__field0),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"enabled" => _serde::__private::Ok(__Field::__field0),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    struct __Visitor<'de> {
                        marker: _serde::__private::PhantomData<Input>,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                        type Value = Input;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct Input",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match match _serde::de::SeqAccess::next_element::<
                                bool,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct Input with 1 element",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(Input { enabled: __field0 })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<bool> = _serde::__private::None;
                            while let _serde::__private::Some(__key)
                                = match _serde::de::MapAccess::next_key::<
                                    __Field,
                                >(&mut __map) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                } {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field(
                                                    "enabled",
                                                ),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                bool,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    _ => {
                                        let _ = match _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        };
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("enabled") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            _serde::__private::Ok(Input { enabled: __field0 })
                        }
                    }
                    const FIELDS: &'static [&'static str] = &["enabled"];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "Input",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<Input>,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        let Input { enabled }: Input = near_sdk::serde_json::from_slice(
                &near_sdk::env::input()
                    .expect("Expected input since method has arguments."),
            )
            .expect("Failed to deserialize input from JSON.");
        let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
        contract.set_whitelist_mode_enabled(enabled);
        near_sdk::env::state_write(&contract);
    }
    #[cfg(target_arch = "wasm32")]
    #[no_mangle]
    pub extern "C" fn get_whitelist_tokens() {
        near_sdk::env::setup_panic_hook();
        let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
        let result = contract.get_whitelist_tokens();
        let result = near_sdk::serde_json::to_vec(&result)
            .expect("Failed to serialize the return value using JSON.");
        near_sdk::env::value_return(&result);
    }
    #[cfg(target_arch = "wasm32")]
    #[no_mangle]
    pub extern "C" fn get_whitelist_accounts() {
        near_sdk::env::setup_panic_hook();
        let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
        let result = contract.get_whitelist_accounts();
        let result = near_sdk::serde_json::to_vec(&result)
            .expect("Failed to serialize the return value using JSON.");
        near_sdk::env::value_return(&result);
    }
}
pub const NO_DEPOSIT: u128 = 0;
pub trait Prover {
    fn verify_log_entry(
        &self,
        log_index: u64,
        log_entry_data: Vec<u8>,
        receipt_index: u64,
        receipt_data: Vec<u8>,
        header_data: Vec<u8>,
        proof: Vec<Vec<u8>>,
        skip_bridge_call: bool,
    ) -> bool;
}
pub mod ext_prover {
    use super::*;
    #[must_use]
    pub struct ProverExt {
        pub(crate) account_id: near_sdk::AccountId,
        pub(crate) deposit: near_sdk::Balance,
        pub(crate) static_gas: near_sdk::Gas,
        pub(crate) gas_weight: near_sdk::GasWeight,
    }
    impl ProverExt {
        pub fn with_attached_deposit(mut self, amount: near_sdk::Balance) -> Self {
            self.deposit = amount;
            self
        }
        pub fn with_static_gas(mut self, static_gas: near_sdk::Gas) -> Self {
            self.static_gas = static_gas;
            self
        }
        pub fn with_unused_gas_weight(mut self, gas_weight: u64) -> Self {
            self.gas_weight = near_sdk::GasWeight(gas_weight);
            self
        }
    }
    /// API for calling this contract's functions in a subsequent execution.
    pub fn ext(account_id: near_sdk::AccountId) -> ProverExt {
        ProverExt {
            account_id,
            deposit: 0,
            static_gas: near_sdk::Gas(0),
            gas_weight: near_sdk::GasWeight::default(),
        }
    }
    impl ProverExt {
        pub fn verify_log_entry(
            self,
            log_index: u64,
            log_entry_data: Vec<u8>,
            receipt_index: u64,
            receipt_data: Vec<u8>,
            header_data: Vec<u8>,
            proof: Vec<Vec<u8>>,
            skip_bridge_call: bool,
        ) -> near_sdk::Promise {
            let __args = {
                struct Input<'nearinput> {
                    log_index: &'nearinput u64,
                    log_entry_data: &'nearinput Vec<u8>,
                    receipt_index: &'nearinput u64,
                    receipt_data: &'nearinput Vec<u8>,
                    header_data: &'nearinput Vec<u8>,
                    proof: &'nearinput Vec<Vec<u8>>,
                    skip_bridge_call: &'nearinput bool,
                }
                impl<'nearinput> borsh::ser::BorshSerialize for Input<'nearinput>
                where
                    &'nearinput u64: borsh::ser::BorshSerialize,
                    &'nearinput Vec<u8>: borsh::ser::BorshSerialize,
                    &'nearinput u64: borsh::ser::BorshSerialize,
                    &'nearinput Vec<u8>: borsh::ser::BorshSerialize,
                    &'nearinput Vec<u8>: borsh::ser::BorshSerialize,
                    &'nearinput Vec<Vec<u8>>: borsh::ser::BorshSerialize,
                    &'nearinput bool: borsh::ser::BorshSerialize,
                {
                    fn serialize<W: borsh::maybestd::io::Write>(
                        &self,
                        writer: &mut W,
                    ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
                        borsh::BorshSerialize::serialize(&self.log_index, writer)?;
                        borsh::BorshSerialize::serialize(&self.log_entry_data, writer)?;
                        borsh::BorshSerialize::serialize(&self.receipt_index, writer)?;
                        borsh::BorshSerialize::serialize(&self.receipt_data, writer)?;
                        borsh::BorshSerialize::serialize(&self.header_data, writer)?;
                        borsh::BorshSerialize::serialize(&self.proof, writer)?;
                        borsh::BorshSerialize::serialize(
                            &self.skip_bridge_call,
                            writer,
                        )?;
                        Ok(())
                    }
                }
                let __args = Input {
                    log_index: &log_index,
                    log_entry_data: &log_entry_data,
                    receipt_index: &receipt_index,
                    receipt_data: &receipt_data,
                    header_data: &header_data,
                    proof: &proof,
                    skip_bridge_call: &skip_bridge_call,
                };
                near_sdk::borsh::BorshSerialize::try_to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using Borsh.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "verify_log_entry".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
    }
}
pub trait EthClient {
    fn last_block_number(&self) -> u64;
}
pub mod ext_eth_client {
    use super::*;
    #[must_use]
    pub struct EthClientExt {
        pub(crate) account_id: near_sdk::AccountId,
        pub(crate) deposit: near_sdk::Balance,
        pub(crate) static_gas: near_sdk::Gas,
        pub(crate) gas_weight: near_sdk::GasWeight,
    }
    impl EthClientExt {
        pub fn with_attached_deposit(mut self, amount: near_sdk::Balance) -> Self {
            self.deposit = amount;
            self
        }
        pub fn with_static_gas(mut self, static_gas: near_sdk::Gas) -> Self {
            self.static_gas = static_gas;
            self
        }
        pub fn with_unused_gas_weight(mut self, gas_weight: u64) -> Self {
            self.gas_weight = near_sdk::GasWeight(gas_weight);
            self
        }
    }
    /// API for calling this contract's functions in a subsequent execution.
    pub fn ext(account_id: near_sdk::AccountId) -> EthClientExt {
        EthClientExt {
            account_id,
            deposit: 0,
            static_gas: near_sdk::Gas(0),
            gas_weight: near_sdk::GasWeight::default(),
        }
    }
    impl EthClientExt {
        pub fn last_block_number(self) -> near_sdk::Promise {
            let __args = ::alloc::vec::Vec::new();
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "last_block_number".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
    }
}
trait NEP141Token {
    fn ft_transfer(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
    );
}
pub mod ext_token {
    use super::*;
    #[must_use]
    pub struct NEP141TokenExt {
        pub(crate) account_id: near_sdk::AccountId,
        pub(crate) deposit: near_sdk::Balance,
        pub(crate) static_gas: near_sdk::Gas,
        pub(crate) gas_weight: near_sdk::GasWeight,
    }
    impl NEP141TokenExt {
        pub fn with_attached_deposit(mut self, amount: near_sdk::Balance) -> Self {
            self.deposit = amount;
            self
        }
        pub fn with_static_gas(mut self, static_gas: near_sdk::Gas) -> Self {
            self.static_gas = static_gas;
            self
        }
        pub fn with_unused_gas_weight(mut self, gas_weight: u64) -> Self {
            self.gas_weight = near_sdk::GasWeight(gas_weight);
            self
        }
    }
    /// API for calling this contract's functions in a subsequent execution.
    pub fn ext(account_id: near_sdk::AccountId) -> NEP141TokenExt {
        NEP141TokenExt {
            account_id,
            deposit: 0,
            static_gas: near_sdk::Gas(0),
            gas_weight: near_sdk::GasWeight::default(),
        }
    }
    impl NEP141TokenExt {
        pub fn ft_transfer(
            self,
            receiver_id: AccountId,
            amount: U128,
            memo: Option<String>,
        ) -> near_sdk::Promise {
            let __args = {
                #[serde(crate = "near_sdk::serde")]
                struct Input<'nearinput> {
                    receiver_id: &'nearinput AccountId,
                    amount: &'nearinput U128,
                    memo: &'nearinput Option<String>,
                }
                #[doc(hidden)]
                #[allow(
                    non_upper_case_globals,
                    unused_attributes,
                    unused_qualifications
                )]
                const _: () = {
                    use near_sdk::serde as _serde;
                    #[automatically_derived]
                    impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                        fn serialize<__S>(
                            &self,
                            __serializer: __S,
                        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                        where
                            __S: near_sdk::serde::Serializer,
                        {
                            let mut __serde_state = match _serde::Serializer::serialize_struct(
                                __serializer,
                                "Input",
                                false as usize + 1 + 1 + 1,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "receiver_id",
                                &self.receiver_id,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "amount",
                                &self.amount,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "memo",
                                &self.memo,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::ser::SerializeStruct::end(__serde_state)
                        }
                    }
                };
                let __args = Input {
                    receiver_id: &receiver_id,
                    amount: &amount,
                    memo: &memo,
                };
                near_sdk::serde_json::to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using JSON.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "ft_transfer".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
    }
}
trait FastBridgeInterface {
    fn withdraw_callback(
        &mut self,
        token_id: AccountId,
        amount: U128,
        sender_id: AccountId,
    );
    fn verify_log_entry_callback(
        &mut self,
        verification_success: bool,
        proof: EthTransferEvent,
    ) -> Promise;
    fn unlock_callback(&self, nonce: U128, recipient_id: AccountId);
    fn init_transfer_callback(
        &mut self,
        transfer_message: TransferMessage,
        sender_id: AccountId,
        update_balance: Option<UpdateBalance>,
    ) -> PromiseOrValue<U128>;
}
pub mod ext_self {
    use super::*;
    #[must_use]
    pub struct FastBridgeInterfaceExt {
        pub(crate) account_id: near_sdk::AccountId,
        pub(crate) deposit: near_sdk::Balance,
        pub(crate) static_gas: near_sdk::Gas,
        pub(crate) gas_weight: near_sdk::GasWeight,
    }
    impl FastBridgeInterfaceExt {
        pub fn with_attached_deposit(mut self, amount: near_sdk::Balance) -> Self {
            self.deposit = amount;
            self
        }
        pub fn with_static_gas(mut self, static_gas: near_sdk::Gas) -> Self {
            self.static_gas = static_gas;
            self
        }
        pub fn with_unused_gas_weight(mut self, gas_weight: u64) -> Self {
            self.gas_weight = near_sdk::GasWeight(gas_weight);
            self
        }
    }
    /// API for calling this contract's functions in a subsequent execution.
    pub fn ext(account_id: near_sdk::AccountId) -> FastBridgeInterfaceExt {
        FastBridgeInterfaceExt {
            account_id,
            deposit: 0,
            static_gas: near_sdk::Gas(0),
            gas_weight: near_sdk::GasWeight::default(),
        }
    }
    impl FastBridgeInterfaceExt {
        pub fn withdraw_callback(
            self,
            token_id: AccountId,
            amount: U128,
            sender_id: AccountId,
        ) -> near_sdk::Promise {
            let __args = {
                #[serde(crate = "near_sdk::serde")]
                struct Input<'nearinput> {
                    token_id: &'nearinput AccountId,
                    amount: &'nearinput U128,
                    sender_id: &'nearinput AccountId,
                }
                #[doc(hidden)]
                #[allow(
                    non_upper_case_globals,
                    unused_attributes,
                    unused_qualifications
                )]
                const _: () = {
                    use near_sdk::serde as _serde;
                    #[automatically_derived]
                    impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                        fn serialize<__S>(
                            &self,
                            __serializer: __S,
                        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                        where
                            __S: near_sdk::serde::Serializer,
                        {
                            let mut __serde_state = match _serde::Serializer::serialize_struct(
                                __serializer,
                                "Input",
                                false as usize + 1 + 1 + 1,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "token_id",
                                &self.token_id,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "amount",
                                &self.amount,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            match _serde::ser::SerializeStruct::serialize_field(
                                &mut __serde_state,
                                "sender_id",
                                &self.sender_id,
                            ) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::ser::SerializeStruct::end(__serde_state)
                        }
                    }
                };
                let __args = Input {
                    token_id: &token_id,
                    amount: &amount,
                    sender_id: &sender_id,
                };
                near_sdk::serde_json::to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using JSON.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "withdraw_callback".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
        pub fn verify_log_entry_callback(
            self,
            proof: EthTransferEvent,
        ) -> near_sdk::Promise {
            let __args = {
                struct Input<'nearinput> {
                    proof: &'nearinput EthTransferEvent,
                }
                impl<'nearinput> borsh::ser::BorshSerialize for Input<'nearinput>
                where
                    &'nearinput EthTransferEvent: borsh::ser::BorshSerialize,
                {
                    fn serialize<W: borsh::maybestd::io::Write>(
                        &self,
                        writer: &mut W,
                    ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
                        borsh::BorshSerialize::serialize(&self.proof, writer)?;
                        Ok(())
                    }
                }
                let __args = Input { proof: &proof };
                near_sdk::borsh::BorshSerialize::try_to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using Borsh.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "verify_log_entry_callback".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
        pub fn unlock_callback(
            self,
            nonce: U128,
            recipient_id: AccountId,
        ) -> near_sdk::Promise {
            let __args = {
                struct Input<'nearinput> {
                    nonce: &'nearinput U128,
                    recipient_id: &'nearinput AccountId,
                }
                impl<'nearinput> borsh::ser::BorshSerialize for Input<'nearinput>
                where
                    &'nearinput U128: borsh::ser::BorshSerialize,
                    &'nearinput AccountId: borsh::ser::BorshSerialize,
                {
                    fn serialize<W: borsh::maybestd::io::Write>(
                        &self,
                        writer: &mut W,
                    ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
                        borsh::BorshSerialize::serialize(&self.nonce, writer)?;
                        borsh::BorshSerialize::serialize(&self.recipient_id, writer)?;
                        Ok(())
                    }
                }
                let __args = Input {
                    nonce: &nonce,
                    recipient_id: &recipient_id,
                };
                near_sdk::borsh::BorshSerialize::try_to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using Borsh.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "unlock_callback".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
        pub fn init_transfer_callback(
            self,
            transfer_message: TransferMessage,
            sender_id: AccountId,
            update_balance: Option<UpdateBalance>,
        ) -> near_sdk::Promise {
            let __args = {
                struct Input<'nearinput> {
                    transfer_message: &'nearinput TransferMessage,
                    sender_id: &'nearinput AccountId,
                    update_balance: &'nearinput Option<UpdateBalance>,
                }
                impl<'nearinput> borsh::ser::BorshSerialize for Input<'nearinput>
                where
                    &'nearinput TransferMessage: borsh::ser::BorshSerialize,
                    &'nearinput AccountId: borsh::ser::BorshSerialize,
                    &'nearinput Option<UpdateBalance>: borsh::ser::BorshSerialize,
                {
                    fn serialize<W: borsh::maybestd::io::Write>(
                        &self,
                        writer: &mut W,
                    ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
                        borsh::BorshSerialize::serialize(
                            &self.transfer_message,
                            writer,
                        )?;
                        borsh::BorshSerialize::serialize(&self.sender_id, writer)?;
                        borsh::BorshSerialize::serialize(&self.update_balance, writer)?;
                        Ok(())
                    }
                }
                let __args = Input {
                    transfer_message: &transfer_message,
                    sender_id: &sender_id,
                    update_balance: &update_balance,
                };
                near_sdk::borsh::BorshSerialize::try_to_vec(&__args)
                    .expect("Failed to serialize the cross contract args using Borsh.")
            };
            near_sdk::Promise::new(self.account_id)
                .function_call_weight(
                    "init_transfer_callback".to_string(),
                    __args,
                    self.deposit,
                    self.static_gas,
                    self.gas_weight,
                )
        }
    }
}
#[serde(crate = "near_sdk::serde")]
pub struct UpdateBalance {
    sender_id: AccountId,
    token: AccountId,
    amount: U128,
}
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    use near_sdk::serde as _serde;
    #[automatically_derived]
    impl near_sdk::serde::Serialize for UpdateBalance {
        fn serialize<__S>(
            &self,
            __serializer: __S,
        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: near_sdk::serde::Serializer,
        {
            let mut __serde_state = match _serde::Serializer::serialize_struct(
                __serializer,
                "UpdateBalance",
                false as usize + 1 + 1 + 1,
            ) {
                _serde::__private::Ok(__val) => __val,
                _serde::__private::Err(__err) => {
                    return _serde::__private::Err(__err);
                }
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "sender_id",
                &self.sender_id,
            ) {
                _serde::__private::Ok(__val) => __val,
                _serde::__private::Err(__err) => {
                    return _serde::__private::Err(__err);
                }
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "token",
                &self.token,
            ) {
                _serde::__private::Ok(__val) => __val,
                _serde::__private::Err(__err) => {
                    return _serde::__private::Err(__err);
                }
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "amount",
                &self.amount,
            ) {
                _serde::__private::Ok(__val) => __val,
                _serde::__private::Err(__err) => {
                    return _serde::__private::Err(__err);
                }
            };
            _serde::ser::SerializeStruct::end(__serde_state)
        }
    }
};
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    use near_sdk::serde as _serde;
    #[automatically_derived]
    impl<'de> near_sdk::serde::Deserialize<'de> for UpdateBalance {
        fn deserialize<__D>(
            __deserializer: __D,
        ) -> near_sdk::serde::__private::Result<Self, __D::Error>
        where
            __D: near_sdk::serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            enum __Field {
                __field0,
                __field1,
                __field2,
                __ignore,
            }
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(
                        __formatter,
                        "field identifier",
                    )
                }
                fn visit_u64<__E>(
                    self,
                    __value: u64,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private::Ok(__Field::__field0),
                        1u64 => _serde::__private::Ok(__Field::__field1),
                        2u64 => _serde::__private::Ok(__Field::__field2),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "sender_id" => _serde::__private::Ok(__Field::__field0),
                        "token" => _serde::__private::Ok(__Field::__field1),
                        "amount" => _serde::__private::Ok(__Field::__field2),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"sender_id" => _serde::__private::Ok(__Field::__field0),
                        b"token" => _serde::__private::Ok(__Field::__field1),
                        b"amount" => _serde::__private::Ok(__Field::__field2),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
            }
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(
                        __deserializer,
                        __FieldVisitor,
                    )
                }
            }
            struct __Visitor<'de> {
                marker: _serde::__private::PhantomData<UpdateBalance>,
                lifetime: _serde::__private::PhantomData<&'de ()>,
            }
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = UpdateBalance;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(
                        __formatter,
                        "struct UpdateBalance",
                    )
                }
                #[inline]
                fn visit_seq<__A>(
                    self,
                    mut __seq: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::SeqAccess<'de>,
                {
                    let __field0 = match match _serde::de::SeqAccess::next_element::<
                        AccountId,
                    >(&mut __seq) {
                        _serde::__private::Ok(__val) => __val,
                        _serde::__private::Err(__err) => {
                            return _serde::__private::Err(__err);
                        }
                    } {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(
                                _serde::de::Error::invalid_length(
                                    0usize,
                                    &"struct UpdateBalance with 3 elements",
                                ),
                            );
                        }
                    };
                    let __field1 = match match _serde::de::SeqAccess::next_element::<
                        AccountId,
                    >(&mut __seq) {
                        _serde::__private::Ok(__val) => __val,
                        _serde::__private::Err(__err) => {
                            return _serde::__private::Err(__err);
                        }
                    } {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(
                                _serde::de::Error::invalid_length(
                                    1usize,
                                    &"struct UpdateBalance with 3 elements",
                                ),
                            );
                        }
                    };
                    let __field2 = match match _serde::de::SeqAccess::next_element::<
                        U128,
                    >(&mut __seq) {
                        _serde::__private::Ok(__val) => __val,
                        _serde::__private::Err(__err) => {
                            return _serde::__private::Err(__err);
                        }
                    } {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(
                                _serde::de::Error::invalid_length(
                                    2usize,
                                    &"struct UpdateBalance with 3 elements",
                                ),
                            );
                        }
                    };
                    _serde::__private::Ok(UpdateBalance {
                        sender_id: __field0,
                        token: __field1,
                        amount: __field2,
                    })
                }
                #[inline]
                fn visit_map<__A>(
                    self,
                    mut __map: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::MapAccess<'de>,
                {
                    let mut __field0: _serde::__private::Option<AccountId> = _serde::__private::None;
                    let mut __field1: _serde::__private::Option<AccountId> = _serde::__private::None;
                    let mut __field2: _serde::__private::Option<U128> = _serde::__private::None;
                    while let _serde::__private::Some(__key)
                        = match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                        match __key {
                            __Field::__field0 => {
                                if _serde::__private::Option::is_some(&__field0) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "sender_id",
                                        ),
                                    );
                                }
                                __field0 = _serde::__private::Some(
                                    match _serde::de::MapAccess::next_value::<
                                        AccountId,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    },
                                );
                            }
                            __Field::__field1 => {
                                if _serde::__private::Option::is_some(&__field1) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("token"),
                                    );
                                }
                                __field1 = _serde::__private::Some(
                                    match _serde::de::MapAccess::next_value::<
                                        AccountId,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    },
                                );
                            }
                            __Field::__field2 => {
                                if _serde::__private::Option::is_some(&__field2) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("amount"),
                                    );
                                }
                                __field2 = _serde::__private::Some(
                                    match _serde::de::MapAccess::next_value::<
                                        U128,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    },
                                );
                            }
                            _ => {
                                let _ = match _serde::de::MapAccess::next_value::<
                                    _serde::de::IgnoredAny,
                                >(&mut __map) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                };
                            }
                        }
                    }
                    let __field0 = match __field0 {
                        _serde::__private::Some(__field0) => __field0,
                        _serde::__private::None => {
                            match _serde::__private::de::missing_field("sender_id") {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        }
                    };
                    let __field1 = match __field1 {
                        _serde::__private::Some(__field1) => __field1,
                        _serde::__private::None => {
                            match _serde::__private::de::missing_field("token") {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        }
                    };
                    let __field2 = match __field2 {
                        _serde::__private::Some(__field2) => __field2,
                        _serde::__private::None => {
                            match _serde::__private::de::missing_field("amount") {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        }
                    };
                    _serde::__private::Ok(UpdateBalance {
                        sender_id: __field0,
                        token: __field1,
                        amount: __field2,
                    })
                }
            }
            const FIELDS: &'static [&'static str] = &["sender_id", "token", "amount"];
            _serde::Deserializer::deserialize_struct(
                __deserializer,
                "UpdateBalance",
                FIELDS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<UpdateBalance>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
impl borsh::de::BorshDeserialize for UpdateBalance
where
    AccountId: borsh::BorshDeserialize,
    AccountId: borsh::BorshDeserialize,
    U128: borsh::BorshDeserialize,
{
    fn deserialize(
        buf: &mut &[u8],
    ) -> ::core::result::Result<Self, borsh::maybestd::io::Error> {
        Ok(Self {
            sender_id: borsh::BorshDeserialize::deserialize(buf)?,
            token: borsh::BorshDeserialize::deserialize(buf)?,
            amount: borsh::BorshDeserialize::deserialize(buf)?,
        })
    }
}
impl borsh::ser::BorshSerialize for UpdateBalance
where
    AccountId: borsh::ser::BorshSerialize,
    AccountId: borsh::ser::BorshSerialize,
    U128: borsh::ser::BorshSerialize,
{
    fn serialize<W: borsh::maybestd::io::Write>(
        &self,
        writer: &mut W,
    ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
        borsh::BorshSerialize::serialize(&self.sender_id, writer)?;
        borsh::BorshSerialize::serialize(&self.token, writer)?;
        borsh::BorshSerialize::serialize(&self.amount, writer)?;
        Ok(())
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for UpdateBalance {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field3_finish(
            f,
            "UpdateBalance",
            "sender_id",
            &&self.sender_id,
            "token",
            &&self.token,
            "amount",
            &&self.amount,
        )
    }
}
#[automatically_derived]
impl ::core::clone::Clone for UpdateBalance {
    #[inline]
    fn clone(&self) -> UpdateBalance {
        UpdateBalance {
            sender_id: ::core::clone::Clone::clone(&self.sender_id),
            token: ::core::clone::Clone::clone(&self.token),
            amount: ::core::clone::Clone::clone(&self.amount),
        }
    }
}
enum StorageKey {
    PendingTransfers,
    UserBalances,
    UserBalancePrefix,
    WhitelistTokens,
    WhitelistAccounts,
    PendingTransfersBalances,
}
impl borsh::ser::BorshSerialize for StorageKey {
    fn serialize<W: borsh::maybestd::io::Write>(
        &self,
        writer: &mut W,
    ) -> core::result::Result<(), borsh::maybestd::io::Error> {
        let variant_idx: u8 = match self {
            StorageKey::PendingTransfers => 0u8,
            StorageKey::UserBalances => 1u8,
            StorageKey::UserBalancePrefix => 2u8,
            StorageKey::WhitelistTokens => 3u8,
            StorageKey::WhitelistAccounts => 4u8,
            StorageKey::PendingTransfersBalances => 5u8,
        };
        writer.write_all(&variant_idx.to_le_bytes())?;
        match self {
            StorageKey::PendingTransfers => {}
            StorageKey::UserBalances => {}
            StorageKey::UserBalancePrefix => {}
            StorageKey::WhitelistTokens => {}
            StorageKey::WhitelistAccounts => {}
            StorageKey::PendingTransfersBalances => {}
        }
        Ok(())
    }
}
impl near_sdk::__private::BorshIntoStorageKey for StorageKey
where
    StorageKey: ::near_sdk::borsh::BorshSerialize,
{}
#[serde(crate = "near_sdk::serde")]
pub struct LockDuration {
    lock_time_min: Duration,
    lock_time_max: Duration,
}
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    use near_sdk::serde as _serde;
    #[automatically_derived]
    impl near_sdk::serde::Serialize for LockDuration {
        fn serialize<__S>(
            &self,
            __serializer: __S,
        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: near_sdk::serde::Serializer,
        {
            let mut __serde_state = match _serde::Serializer::serialize_struct(
                __serializer,
                "LockDuration",
                false as usize + 1 + 1,
            ) {
                _serde::__private::Ok(__val) => __val,
                _serde::__private::Err(__err) => {
                    return _serde::__private::Err(__err);
                }
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "lock_time_min",
                &self.lock_time_min,
            ) {
                _serde::__private::Ok(__val) => __val,
                _serde::__private::Err(__err) => {
                    return _serde::__private::Err(__err);
                }
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "lock_time_max",
                &self.lock_time_max,
            ) {
                _serde::__private::Ok(__val) => __val,
                _serde::__private::Err(__err) => {
                    return _serde::__private::Err(__err);
                }
            };
            _serde::ser::SerializeStruct::end(__serde_state)
        }
    }
};
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    use near_sdk::serde as _serde;
    #[automatically_derived]
    impl<'de> near_sdk::serde::Deserialize<'de> for LockDuration {
        fn deserialize<__D>(
            __deserializer: __D,
        ) -> near_sdk::serde::__private::Result<Self, __D::Error>
        where
            __D: near_sdk::serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            enum __Field {
                __field0,
                __field1,
                __ignore,
            }
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(
                        __formatter,
                        "field identifier",
                    )
                }
                fn visit_u64<__E>(
                    self,
                    __value: u64,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private::Ok(__Field::__field0),
                        1u64 => _serde::__private::Ok(__Field::__field1),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "lock_time_min" => _serde::__private::Ok(__Field::__field0),
                        "lock_time_max" => _serde::__private::Ok(__Field::__field1),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"lock_time_min" => _serde::__private::Ok(__Field::__field0),
                        b"lock_time_max" => _serde::__private::Ok(__Field::__field1),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
            }
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(
                        __deserializer,
                        __FieldVisitor,
                    )
                }
            }
            struct __Visitor<'de> {
                marker: _serde::__private::PhantomData<LockDuration>,
                lifetime: _serde::__private::PhantomData<&'de ()>,
            }
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = LockDuration;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(
                        __formatter,
                        "struct LockDuration",
                    )
                }
                #[inline]
                fn visit_seq<__A>(
                    self,
                    mut __seq: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::SeqAccess<'de>,
                {
                    let __field0 = match match _serde::de::SeqAccess::next_element::<
                        Duration,
                    >(&mut __seq) {
                        _serde::__private::Ok(__val) => __val,
                        _serde::__private::Err(__err) => {
                            return _serde::__private::Err(__err);
                        }
                    } {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(
                                _serde::de::Error::invalid_length(
                                    0usize,
                                    &"struct LockDuration with 2 elements",
                                ),
                            );
                        }
                    };
                    let __field1 = match match _serde::de::SeqAccess::next_element::<
                        Duration,
                    >(&mut __seq) {
                        _serde::__private::Ok(__val) => __val,
                        _serde::__private::Err(__err) => {
                            return _serde::__private::Err(__err);
                        }
                    } {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(
                                _serde::de::Error::invalid_length(
                                    1usize,
                                    &"struct LockDuration with 2 elements",
                                ),
                            );
                        }
                    };
                    _serde::__private::Ok(LockDuration {
                        lock_time_min: __field0,
                        lock_time_max: __field1,
                    })
                }
                #[inline]
                fn visit_map<__A>(
                    self,
                    mut __map: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::MapAccess<'de>,
                {
                    let mut __field0: _serde::__private::Option<Duration> = _serde::__private::None;
                    let mut __field1: _serde::__private::Option<Duration> = _serde::__private::None;
                    while let _serde::__private::Some(__key)
                        = match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                        match __key {
                            __Field::__field0 => {
                                if _serde::__private::Option::is_some(&__field0) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "lock_time_min",
                                        ),
                                    );
                                }
                                __field0 = _serde::__private::Some(
                                    match _serde::de::MapAccess::next_value::<
                                        Duration,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    },
                                );
                            }
                            __Field::__field1 => {
                                if _serde::__private::Option::is_some(&__field1) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "lock_time_max",
                                        ),
                                    );
                                }
                                __field1 = _serde::__private::Some(
                                    match _serde::de::MapAccess::next_value::<
                                        Duration,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    },
                                );
                            }
                            _ => {
                                let _ = match _serde::de::MapAccess::next_value::<
                                    _serde::de::IgnoredAny,
                                >(&mut __map) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                };
                            }
                        }
                    }
                    let __field0 = match __field0 {
                        _serde::__private::Some(__field0) => __field0,
                        _serde::__private::None => {
                            match _serde::__private::de::missing_field("lock_time_min") {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        }
                    };
                    let __field1 = match __field1 {
                        _serde::__private::Some(__field1) => __field1,
                        _serde::__private::None => {
                            match _serde::__private::de::missing_field("lock_time_max") {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        }
                    };
                    _serde::__private::Ok(LockDuration {
                        lock_time_min: __field0,
                        lock_time_max: __field1,
                    })
                }
            }
            const FIELDS: &'static [&'static str] = &["lock_time_min", "lock_time_max"];
            _serde::Deserializer::deserialize_struct(
                __deserializer,
                "LockDuration",
                FIELDS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<LockDuration>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
impl borsh::de::BorshDeserialize for LockDuration
where
    Duration: borsh::BorshDeserialize,
    Duration: borsh::BorshDeserialize,
{
    fn deserialize(
        buf: &mut &[u8],
    ) -> ::core::result::Result<Self, borsh::maybestd::io::Error> {
        Ok(Self {
            lock_time_min: borsh::BorshDeserialize::deserialize(buf)?,
            lock_time_max: borsh::BorshDeserialize::deserialize(buf)?,
        })
    }
}
impl borsh::ser::BorshSerialize for LockDuration
where
    Duration: borsh::ser::BorshSerialize,
    Duration: borsh::ser::BorshSerialize,
{
    fn serialize<W: borsh::maybestd::io::Write>(
        &self,
        writer: &mut W,
    ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
        borsh::BorshSerialize::serialize(&self.lock_time_min, writer)?;
        borsh::BorshSerialize::serialize(&self.lock_time_max, writer)?;
        Ok(())
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for LockDuration {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field2_finish(
            f,
            "LockDuration",
            "lock_time_min",
            &&self.lock_time_min,
            "lock_time_max",
            &&self.lock_time_max,
        )
    }
}
#[automatically_derived]
impl ::core::clone::Clone for LockDuration {
    #[inline]
    fn clone(&self) -> LockDuration {
        LockDuration {
            lock_time_min: ::core::clone::Clone::clone(&self.lock_time_min),
            lock_time_max: ::core::clone::Clone::clone(&self.lock_time_max),
        }
    }
}
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
struct __AclBoundchecker<T: Copy + Clone> {
    _marker: ::std::marker::PhantomData<T>,
}
impl<T: Copy + Clone> __AclBoundchecker<T> {
    fn new() -> Self {
        Self {
            _marker: Default::default(),
        }
    }
}
impl Role {
    fn check_bounds() {
        let _x = __AclBoundchecker::<Role>::new();
    }
}
impl From<Role> for u8 {
    fn from(value: Role) -> Self {
        match value {
            Role::PauseManager => 0u8,
            Role::UnrestrictedUnlock => 1u8,
            Role::UnrestrictedLpUnlock => 2u8,
            Role::UnrestrictedWithdraw => 3u8,
            Role::WhitelistManager => 4u8,
            Role::ConfigManager => 5u8,
        }
    }
}
impl ::std::convert::TryFrom<u8> for Role {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0u8 => Ok(Role::PauseManager),
            1u8 => Ok(Role::UnrestrictedUnlock),
            2u8 => Ok(Role::UnrestrictedLpUnlock),
            3u8 => Ok(Role::UnrestrictedWithdraw),
            4u8 => Ok(Role::WhitelistManager),
            5u8 => Ok(Role::ConfigManager),
            _ => Err("Value does not correspond to a variant"),
        }
    }
}
impl From<Role> for &'static str {
    fn from(value: Role) -> Self {
        match value {
            Role::PauseManager => "PauseManager",
            Role::UnrestrictedUnlock => "UnrestrictedUnlock",
            Role::UnrestrictedLpUnlock => "UnrestrictedLpUnlock",
            Role::UnrestrictedWithdraw => "UnrestrictedWithdraw",
            Role::WhitelistManager => "WhitelistManager",
            Role::ConfigManager => "ConfigManager",
        }
    }
}
impl From<Role> for String {
    fn from(value: Role) -> Self {
        match value {
            Role::PauseManager => "PauseManager".to_string(),
            Role::UnrestrictedUnlock => "UnrestrictedUnlock".to_string(),
            Role::UnrestrictedLpUnlock => "UnrestrictedLpUnlock".to_string(),
            Role::UnrestrictedWithdraw => "UnrestrictedWithdraw".to_string(),
            Role::WhitelistManager => "WhitelistManager".to_string(),
            Role::ConfigManager => "ConfigManager".to_string(),
        }
    }
}
impl ::std::convert::TryFrom<&str> for Role {
    type Error = &'static str;
    fn try_from(value: &str) -> Result<Role, Self::Error> {
        match value {
            "PauseManager" => Ok(Role::PauseManager),
            "UnrestrictedUnlock" => Ok(Role::UnrestrictedUnlock),
            "UnrestrictedLpUnlock" => Ok(Role::UnrestrictedLpUnlock),
            "UnrestrictedWithdraw" => Ok(Role::UnrestrictedWithdraw),
            "WhitelistManager" => Ok(Role::WhitelistManager),
            "ConfigManager" => Ok(Role::ConfigManager),
            _ => Err("Value does not correspond to a variant"),
        }
    }
}
/// Panics if `n` is too large.
fn safe_leftshift(value: u128, n: u8) -> u128 {
    value
        .checked_shl(n.into())
        .unwrap_or_else(|| ::near_sdk::env::panic_str(
            "Too many enum variants to be represented by bitflags",
        ))
}
impl AccessControlRole for Role {
    fn acl_super_admin_permission() -> u128 {
        1
    }
    fn acl_permission(self) -> u128 {
        let n = (u8::from(self) + 1)
            .checked_mul(2)
            .unwrap_or_else(|| ::near_sdk::env::panic_str("Too many enum variants")) - 1;
        safe_leftshift(1, n)
    }
    fn acl_admin_permission(self) -> u128 {
        let n = (u8::from(self) + 1)
            .checked_mul(2)
            .unwrap_or_else(|| ::near_sdk::env::panic_str("Too many enum variants"));
        safe_leftshift(1, n)
    }
}
/// Encodes permissions for roles and admins.
struct RoleFlags {
    bits: u128,
}
#[automatically_derived]
impl ::core::marker::Copy for RoleFlags {}
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for RoleFlags {}
#[automatically_derived]
impl ::core::cmp::PartialEq for RoleFlags {
    #[inline]
    fn eq(&self, other: &RoleFlags) -> bool {
        self.bits == other.bits
    }
}
#[automatically_derived]
impl ::core::marker::StructuralEq for RoleFlags {}
#[automatically_derived]
impl ::core::cmp::Eq for RoleFlags {
    #[inline]
    #[doc(hidden)]
    #[no_coverage]
    fn assert_receiver_is_total_eq(&self) -> () {
        let _: ::core::cmp::AssertParamIsEq<u128>;
    }
}
#[automatically_derived]
impl ::core::clone::Clone for RoleFlags {
    #[inline]
    fn clone(&self) -> RoleFlags {
        let _: ::core::clone::AssertParamIsClone<u128>;
        *self
    }
}
#[automatically_derived]
impl ::core::cmp::PartialOrd for RoleFlags {
    #[inline]
    fn partial_cmp(
        &self,
        other: &RoleFlags,
    ) -> ::core::option::Option<::core::cmp::Ordering> {
        ::core::cmp::PartialOrd::partial_cmp(&self.bits, &other.bits)
    }
}
#[automatically_derived]
impl ::core::cmp::Ord for RoleFlags {
    #[inline]
    fn cmp(&self, other: &RoleFlags) -> ::core::cmp::Ordering {
        ::core::cmp::Ord::cmp(&self.bits, &other.bits)
    }
}
#[automatically_derived]
impl ::core::hash::Hash for RoleFlags {
    fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) -> () {
        ::core::hash::Hash::hash(&self.bits, state)
    }
}
impl borsh::de::BorshDeserialize for RoleFlags
where
    u128: borsh::BorshDeserialize,
{
    fn deserialize(
        buf: &mut &[u8],
    ) -> ::core::result::Result<Self, borsh::maybestd::io::Error> {
        Ok(Self {
            bits: borsh::BorshDeserialize::deserialize(buf)?,
        })
    }
}
impl borsh::ser::BorshSerialize for RoleFlags
where
    u128: borsh::ser::BorshSerialize,
{
    fn serialize<W: borsh::maybestd::io::Write>(
        &self,
        writer: &mut W,
    ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
        borsh::BorshSerialize::serialize(&self.bits, writer)?;
        Ok(())
    }
}
#[automatically_derived]
impl ::core::default::Default for RoleFlags {
    #[inline]
    fn default() -> RoleFlags {
        RoleFlags {
            bits: ::core::default::Default::default(),
        }
    }
}
impl ::bitflags::_core::fmt::Debug for RoleFlags {
    fn fmt(
        &self,
        f: &mut ::bitflags::_core::fmt::Formatter,
    ) -> ::bitflags::_core::fmt::Result {
        #[allow(non_snake_case)]
        trait __BitFlags {
            #[inline]
            fn __SUPER_ADMIN(&self) -> bool {
                false
            }
            #[inline]
            fn PAUSEMANAGER(&self) -> bool {
                false
            }
            #[inline]
            fn PAUSEMANAGER_ADMIN(&self) -> bool {
                false
            }
            #[inline]
            fn UNRESTRICTEDUNLOCK(&self) -> bool {
                false
            }
            #[inline]
            fn UNRESTRICTEDUNLOCK_ADMIN(&self) -> bool {
                false
            }
            #[inline]
            fn UNRESTRICTEDLPUNLOCK(&self) -> bool {
                false
            }
            #[inline]
            fn UNRESTRICTEDLPUNLOCK_ADMIN(&self) -> bool {
                false
            }
            #[inline]
            fn UNRESTRICTEDWITHDRAW(&self) -> bool {
                false
            }
            #[inline]
            fn UNRESTRICTEDWITHDRAW_ADMIN(&self) -> bool {
                false
            }
            #[inline]
            fn WHITELISTMANAGER(&self) -> bool {
                false
            }
            #[inline]
            fn WHITELISTMANAGER_ADMIN(&self) -> bool {
                false
            }
            #[inline]
            fn CONFIGMANAGER(&self) -> bool {
                false
            }
            #[inline]
            fn CONFIGMANAGER_ADMIN(&self) -> bool {
                false
            }
        }
        #[allow(non_snake_case)]
        impl __BitFlags for RoleFlags {
            #[allow(deprecated)]
            #[inline]
            fn __SUPER_ADMIN(&self) -> bool {
                if Self::__SUPER_ADMIN.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::__SUPER_ADMIN.bits == Self::__SUPER_ADMIN.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn PAUSEMANAGER(&self) -> bool {
                if Self::PAUSEMANAGER.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::PAUSEMANAGER.bits == Self::PAUSEMANAGER.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn PAUSEMANAGER_ADMIN(&self) -> bool {
                if Self::PAUSEMANAGER_ADMIN.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::PAUSEMANAGER_ADMIN.bits
                        == Self::PAUSEMANAGER_ADMIN.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn UNRESTRICTEDUNLOCK(&self) -> bool {
                if Self::UNRESTRICTEDUNLOCK.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::UNRESTRICTEDUNLOCK.bits
                        == Self::UNRESTRICTEDUNLOCK.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn UNRESTRICTEDUNLOCK_ADMIN(&self) -> bool {
                if Self::UNRESTRICTEDUNLOCK_ADMIN.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::UNRESTRICTEDUNLOCK_ADMIN.bits
                        == Self::UNRESTRICTEDUNLOCK_ADMIN.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn UNRESTRICTEDLPUNLOCK(&self) -> bool {
                if Self::UNRESTRICTEDLPUNLOCK.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::UNRESTRICTEDLPUNLOCK.bits
                        == Self::UNRESTRICTEDLPUNLOCK.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn UNRESTRICTEDLPUNLOCK_ADMIN(&self) -> bool {
                if Self::UNRESTRICTEDLPUNLOCK_ADMIN.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::UNRESTRICTEDLPUNLOCK_ADMIN.bits
                        == Self::UNRESTRICTEDLPUNLOCK_ADMIN.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn UNRESTRICTEDWITHDRAW(&self) -> bool {
                if Self::UNRESTRICTEDWITHDRAW.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::UNRESTRICTEDWITHDRAW.bits
                        == Self::UNRESTRICTEDWITHDRAW.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn UNRESTRICTEDWITHDRAW_ADMIN(&self) -> bool {
                if Self::UNRESTRICTEDWITHDRAW_ADMIN.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::UNRESTRICTEDWITHDRAW_ADMIN.bits
                        == Self::UNRESTRICTEDWITHDRAW_ADMIN.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn WHITELISTMANAGER(&self) -> bool {
                if Self::WHITELISTMANAGER.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::WHITELISTMANAGER.bits
                        == Self::WHITELISTMANAGER.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn WHITELISTMANAGER_ADMIN(&self) -> bool {
                if Self::WHITELISTMANAGER_ADMIN.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::WHITELISTMANAGER_ADMIN.bits
                        == Self::WHITELISTMANAGER_ADMIN.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn CONFIGMANAGER(&self) -> bool {
                if Self::CONFIGMANAGER.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::CONFIGMANAGER.bits == Self::CONFIGMANAGER.bits
                }
            }
            #[allow(deprecated)]
            #[inline]
            fn CONFIGMANAGER_ADMIN(&self) -> bool {
                if Self::CONFIGMANAGER_ADMIN.bits == 0 && self.bits != 0 {
                    false
                } else {
                    self.bits & Self::CONFIGMANAGER_ADMIN.bits
                        == Self::CONFIGMANAGER_ADMIN.bits
                }
            }
        }
        let mut first = true;
        if <Self as __BitFlags>::__SUPER_ADMIN(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("__SUPER_ADMIN")?;
        }
        if <Self as __BitFlags>::PAUSEMANAGER(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("PAUSEMANAGER")?;
        }
        if <Self as __BitFlags>::PAUSEMANAGER_ADMIN(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("PAUSEMANAGER_ADMIN")?;
        }
        if <Self as __BitFlags>::UNRESTRICTEDUNLOCK(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("UNRESTRICTEDUNLOCK")?;
        }
        if <Self as __BitFlags>::UNRESTRICTEDUNLOCK_ADMIN(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("UNRESTRICTEDUNLOCK_ADMIN")?;
        }
        if <Self as __BitFlags>::UNRESTRICTEDLPUNLOCK(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("UNRESTRICTEDLPUNLOCK")?;
        }
        if <Self as __BitFlags>::UNRESTRICTEDLPUNLOCK_ADMIN(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("UNRESTRICTEDLPUNLOCK_ADMIN")?;
        }
        if <Self as __BitFlags>::UNRESTRICTEDWITHDRAW(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("UNRESTRICTEDWITHDRAW")?;
        }
        if <Self as __BitFlags>::UNRESTRICTEDWITHDRAW_ADMIN(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("UNRESTRICTEDWITHDRAW_ADMIN")?;
        }
        if <Self as __BitFlags>::WHITELISTMANAGER(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("WHITELISTMANAGER")?;
        }
        if <Self as __BitFlags>::WHITELISTMANAGER_ADMIN(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("WHITELISTMANAGER_ADMIN")?;
        }
        if <Self as __BitFlags>::CONFIGMANAGER(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("CONFIGMANAGER")?;
        }
        if <Self as __BitFlags>::CONFIGMANAGER_ADMIN(self) {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("CONFIGMANAGER_ADMIN")?;
        }
        let extra_bits = self.bits & !Self::all().bits();
        if extra_bits != 0 {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str("0x")?;
            ::bitflags::_core::fmt::LowerHex::fmt(&extra_bits, f)?;
        }
        if first {
            f.write_str("(empty)")?;
        }
        Ok(())
    }
}
impl ::bitflags::_core::fmt::Binary for RoleFlags {
    fn fmt(
        &self,
        f: &mut ::bitflags::_core::fmt::Formatter,
    ) -> ::bitflags::_core::fmt::Result {
        ::bitflags::_core::fmt::Binary::fmt(&self.bits, f)
    }
}
impl ::bitflags::_core::fmt::Octal for RoleFlags {
    fn fmt(
        &self,
        f: &mut ::bitflags::_core::fmt::Formatter,
    ) -> ::bitflags::_core::fmt::Result {
        ::bitflags::_core::fmt::Octal::fmt(&self.bits, f)
    }
}
impl ::bitflags::_core::fmt::LowerHex for RoleFlags {
    fn fmt(
        &self,
        f: &mut ::bitflags::_core::fmt::Formatter,
    ) -> ::bitflags::_core::fmt::Result {
        ::bitflags::_core::fmt::LowerHex::fmt(&self.bits, f)
    }
}
impl ::bitflags::_core::fmt::UpperHex for RoleFlags {
    fn fmt(
        &self,
        f: &mut ::bitflags::_core::fmt::Formatter,
    ) -> ::bitflags::_core::fmt::Result {
        ::bitflags::_core::fmt::UpperHex::fmt(&self.bits, f)
    }
}
#[allow(dead_code)]
impl RoleFlags {
    pub const __SUPER_ADMIN: Self = Self { bits: 1u128 << 0u8 };
    pub const PAUSEMANAGER: Self = Self { bits: 1u128 << 1u8 };
    pub const PAUSEMANAGER_ADMIN: Self = Self { bits: 1u128 << 2u8 };
    pub const UNRESTRICTEDUNLOCK: Self = Self { bits: 1u128 << 3u8 };
    pub const UNRESTRICTEDUNLOCK_ADMIN: Self = Self { bits: 1u128 << 4u8 };
    pub const UNRESTRICTEDLPUNLOCK: Self = Self { bits: 1u128 << 5u8 };
    pub const UNRESTRICTEDLPUNLOCK_ADMIN: Self = Self { bits: 1u128 << 6u8 };
    pub const UNRESTRICTEDWITHDRAW: Self = Self { bits: 1u128 << 7u8 };
    pub const UNRESTRICTEDWITHDRAW_ADMIN: Self = Self { bits: 1u128 << 8u8 };
    pub const WHITELISTMANAGER: Self = Self { bits: 1u128 << 9u8 };
    pub const WHITELISTMANAGER_ADMIN: Self = Self { bits: 1u128 << 10u8 };
    pub const CONFIGMANAGER: Self = Self { bits: 1u128 << 11u8 };
    pub const CONFIGMANAGER_ADMIN: Self = Self { bits: 1u128 << 12u8 };
    /// Returns an empty set of flags.
    #[inline]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }
    /// Returns the set containing all flags.
    #[inline]
    pub const fn all() -> Self {
        #[allow(non_snake_case)]
        trait __BitFlags {
            const __SUPER_ADMIN: u128 = 0;
            const PAUSEMANAGER: u128 = 0;
            const PAUSEMANAGER_ADMIN: u128 = 0;
            const UNRESTRICTEDUNLOCK: u128 = 0;
            const UNRESTRICTEDUNLOCK_ADMIN: u128 = 0;
            const UNRESTRICTEDLPUNLOCK: u128 = 0;
            const UNRESTRICTEDLPUNLOCK_ADMIN: u128 = 0;
            const UNRESTRICTEDWITHDRAW: u128 = 0;
            const UNRESTRICTEDWITHDRAW_ADMIN: u128 = 0;
            const WHITELISTMANAGER: u128 = 0;
            const WHITELISTMANAGER_ADMIN: u128 = 0;
            const CONFIGMANAGER: u128 = 0;
            const CONFIGMANAGER_ADMIN: u128 = 0;
        }
        #[allow(non_snake_case)]
        impl __BitFlags for RoleFlags {
            #[allow(deprecated)]
            const __SUPER_ADMIN: u128 = Self::__SUPER_ADMIN.bits;
            #[allow(deprecated)]
            const PAUSEMANAGER: u128 = Self::PAUSEMANAGER.bits;
            #[allow(deprecated)]
            const PAUSEMANAGER_ADMIN: u128 = Self::PAUSEMANAGER_ADMIN.bits;
            #[allow(deprecated)]
            const UNRESTRICTEDUNLOCK: u128 = Self::UNRESTRICTEDUNLOCK.bits;
            #[allow(deprecated)]
            const UNRESTRICTEDUNLOCK_ADMIN: u128 = Self::UNRESTRICTEDUNLOCK_ADMIN.bits;
            #[allow(deprecated)]
            const UNRESTRICTEDLPUNLOCK: u128 = Self::UNRESTRICTEDLPUNLOCK.bits;
            #[allow(deprecated)]
            const UNRESTRICTEDLPUNLOCK_ADMIN: u128 = Self::UNRESTRICTEDLPUNLOCK_ADMIN
                .bits;
            #[allow(deprecated)]
            const UNRESTRICTEDWITHDRAW: u128 = Self::UNRESTRICTEDWITHDRAW.bits;
            #[allow(deprecated)]
            const UNRESTRICTEDWITHDRAW_ADMIN: u128 = Self::UNRESTRICTEDWITHDRAW_ADMIN
                .bits;
            #[allow(deprecated)]
            const WHITELISTMANAGER: u128 = Self::WHITELISTMANAGER.bits;
            #[allow(deprecated)]
            const WHITELISTMANAGER_ADMIN: u128 = Self::WHITELISTMANAGER_ADMIN.bits;
            #[allow(deprecated)]
            const CONFIGMANAGER: u128 = Self::CONFIGMANAGER.bits;
            #[allow(deprecated)]
            const CONFIGMANAGER_ADMIN: u128 = Self::CONFIGMANAGER_ADMIN.bits;
        }
        Self {
            bits: <Self as __BitFlags>::__SUPER_ADMIN
                | <Self as __BitFlags>::PAUSEMANAGER
                | <Self as __BitFlags>::PAUSEMANAGER_ADMIN
                | <Self as __BitFlags>::UNRESTRICTEDUNLOCK
                | <Self as __BitFlags>::UNRESTRICTEDUNLOCK_ADMIN
                | <Self as __BitFlags>::UNRESTRICTEDLPUNLOCK
                | <Self as __BitFlags>::UNRESTRICTEDLPUNLOCK_ADMIN
                | <Self as __BitFlags>::UNRESTRICTEDWITHDRAW
                | <Self as __BitFlags>::UNRESTRICTEDWITHDRAW_ADMIN
                | <Self as __BitFlags>::WHITELISTMANAGER
                | <Self as __BitFlags>::WHITELISTMANAGER_ADMIN
                | <Self as __BitFlags>::CONFIGMANAGER
                | <Self as __BitFlags>::CONFIGMANAGER_ADMIN,
        }
    }
    /// Returns the raw value of the flags currently stored.
    #[inline]
    pub const fn bits(&self) -> u128 {
        self.bits
    }
    /// Convert from underlying bit representation, unless that
    /// representation contains bits that do not correspond to a flag.
    #[inline]
    pub const fn from_bits(bits: u128) -> ::bitflags::_core::option::Option<Self> {
        if (bits & !Self::all().bits()) == 0 {
            ::bitflags::_core::option::Option::Some(Self { bits })
        } else {
            ::bitflags::_core::option::Option::None
        }
    }
    /// Convert from underlying bit representation, dropping any bits
    /// that do not correspond to flags.
    #[inline]
    pub const fn from_bits_truncate(bits: u128) -> Self {
        Self {
            bits: bits & Self::all().bits,
        }
    }
    /// Convert from underlying bit representation, preserving all
    /// bits (even those not corresponding to a defined flag).
    ///
    /// # Safety
    ///
    /// The caller of the `bitflags!` macro can chose to allow or
    /// disallow extra bits for their bitflags type.
    ///
    /// The caller of `from_bits_unchecked()` has to ensure that
    /// all bits correspond to a defined flag or that extra bits
    /// are valid for this bitflags type.
    #[inline]
    pub const unsafe fn from_bits_unchecked(bits: u128) -> Self {
        Self { bits }
    }
    /// Returns `true` if no flags are currently stored.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.bits() == Self::empty().bits()
    }
    /// Returns `true` if all flags are currently set.
    #[inline]
    pub const fn is_all(&self) -> bool {
        Self::all().bits | self.bits == self.bits
    }
    /// Returns `true` if there are flags common to both `self` and `other`.
    #[inline]
    pub const fn intersects(&self, other: Self) -> bool {
        !(Self {
            bits: self.bits & other.bits,
        })
            .is_empty()
    }
    /// Returns `true` if all of the flags in `other` are contained within `self`.
    #[inline]
    pub const fn contains(&self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }
    /// Inserts the specified flags in-place.
    #[inline]
    pub fn insert(&mut self, other: Self) {
        self.bits |= other.bits;
    }
    /// Removes the specified flags in-place.
    #[inline]
    pub fn remove(&mut self, other: Self) {
        self.bits &= !other.bits;
    }
    /// Toggles the specified flags in-place.
    #[inline]
    pub fn toggle(&mut self, other: Self) {
        self.bits ^= other.bits;
    }
    /// Inserts or removes the specified flags depending on the passed value.
    #[inline]
    pub fn set(&mut self, other: Self, value: bool) {
        if value {
            self.insert(other);
        } else {
            self.remove(other);
        }
    }
    /// Returns the intersection between the flags in `self` and
    /// `other`.
    ///
    /// Specifically, the returned set contains only the flags which are
    /// present in *both* `self` *and* `other`.
    ///
    /// This is equivalent to using the `&` operator (e.g.
    /// [`ops::BitAnd`]), as in `flags & other`.
    ///
    /// [`ops::BitAnd`]: https://doc.rust-lang.org/std/ops/trait.BitAnd.html
    #[inline]
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }
    /// Returns the union of between the flags in `self` and `other`.
    ///
    /// Specifically, the returned set contains all flags which are
    /// present in *either* `self` *or* `other`, including any which are
    /// present in both (see [`Self::symmetric_difference`] if that
    /// is undesirable).
    ///
    /// This is equivalent to using the `|` operator (e.g.
    /// [`ops::BitOr`]), as in `flags | other`.
    ///
    /// [`ops::BitOr`]: https://doc.rust-lang.org/std/ops/trait.BitOr.html
    #[inline]
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }
    /// Returns the difference between the flags in `self` and `other`.
    ///
    /// Specifically, the returned set contains all flags present in
    /// `self`, except for the ones present in `other`.
    ///
    /// It is also conceptually equivalent to the "bit-clear" operation:
    /// `flags & !other` (and this syntax is also supported).
    ///
    /// This is equivalent to using the `-` operator (e.g.
    /// [`ops::Sub`]), as in `flags - other`.
    ///
    /// [`ops::Sub`]: https://doc.rust-lang.org/std/ops/trait.Sub.html
    #[inline]
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self {
            bits: self.bits & !other.bits,
        }
    }
    /// Returns the [symmetric difference][sym-diff] between the flags
    /// in `self` and `other`.
    ///
    /// Specifically, the returned set contains the flags present which
    /// are present in `self` or `other`, but that are not present in
    /// both. Equivalently, it contains the flags present in *exactly
    /// one* of the sets `self` and `other`.
    ///
    /// This is equivalent to using the `^` operator (e.g.
    /// [`ops::BitXor`]), as in `flags ^ other`.
    ///
    /// [sym-diff]: https://en.wikipedia.org/wiki/Symmetric_difference
    /// [`ops::BitXor`]: https://doc.rust-lang.org/std/ops/trait.BitXor.html
    #[inline]
    #[must_use]
    pub const fn symmetric_difference(self, other: Self) -> Self {
        Self {
            bits: self.bits ^ other.bits,
        }
    }
    /// Returns the complement of this set of flags.
    ///
    /// Specifically, the returned set contains all the flags which are
    /// not set in `self`, but which are allowed for this type.
    ///
    /// Alternatively, it can be thought of as the set difference
    /// between [`Self::all()`] and `self` (e.g. `Self::all() - self`)
    ///
    /// This is equivalent to using the `!` operator (e.g.
    /// [`ops::Not`]), as in `!flags`.
    ///
    /// [`Self::all()`]: Self::all
    /// [`ops::Not`]: https://doc.rust-lang.org/std/ops/trait.Not.html
    #[inline]
    #[must_use]
    pub const fn complement(self) -> Self {
        Self::from_bits_truncate(!self.bits)
    }
}
impl ::bitflags::_core::ops::BitOr for RoleFlags {
    type Output = Self;
    /// Returns the union of the two sets of flags.
    #[inline]
    fn bitor(self, other: RoleFlags) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }
}
impl ::bitflags::_core::ops::BitOrAssign for RoleFlags {
    /// Adds the set of flags.
    #[inline]
    fn bitor_assign(&mut self, other: Self) {
        self.bits |= other.bits;
    }
}
impl ::bitflags::_core::ops::BitXor for RoleFlags {
    type Output = Self;
    /// Returns the left flags, but with all the right flags toggled.
    #[inline]
    fn bitxor(self, other: Self) -> Self {
        Self {
            bits: self.bits ^ other.bits,
        }
    }
}
impl ::bitflags::_core::ops::BitXorAssign for RoleFlags {
    /// Toggles the set of flags.
    #[inline]
    fn bitxor_assign(&mut self, other: Self) {
        self.bits ^= other.bits;
    }
}
impl ::bitflags::_core::ops::BitAnd for RoleFlags {
    type Output = Self;
    /// Returns the intersection between the two sets of flags.
    #[inline]
    fn bitand(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }
}
impl ::bitflags::_core::ops::BitAndAssign for RoleFlags {
    /// Disables all flags disabled in the set.
    #[inline]
    fn bitand_assign(&mut self, other: Self) {
        self.bits &= other.bits;
    }
}
impl ::bitflags::_core::ops::Sub for RoleFlags {
    type Output = Self;
    /// Returns the set difference of the two sets of flags.
    #[inline]
    fn sub(self, other: Self) -> Self {
        Self {
            bits: self.bits & !other.bits,
        }
    }
}
impl ::bitflags::_core::ops::SubAssign for RoleFlags {
    /// Disables all flags enabled in the set.
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        self.bits &= !other.bits;
    }
}
impl ::bitflags::_core::ops::Not for RoleFlags {
    type Output = Self;
    /// Returns the complement of this set of flags.
    #[inline]
    fn not(self) -> Self {
        Self { bits: !self.bits } & Self::all()
    }
}
impl ::bitflags::_core::iter::Extend<RoleFlags> for RoleFlags {
    fn extend<T: ::bitflags::_core::iter::IntoIterator<Item = Self>>(
        &mut self,
        iterator: T,
    ) {
        for item in iterator {
            self.insert(item)
        }
    }
}
impl ::bitflags::_core::iter::FromIterator<RoleFlags> for RoleFlags {
    fn from_iter<T: ::bitflags::_core::iter::IntoIterator<Item = Self>>(
        iterator: T,
    ) -> Self {
        let mut result = Self::empty();
        result.extend(iterator);
        result
    }
}
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    use near_sdk::serde as _serde;
    #[automatically_derived]
    impl<'de> near_sdk::serde::Deserialize<'de> for Role {
        fn deserialize<__D>(
            __deserializer: __D,
        ) -> near_sdk::serde::__private::Result<Self, __D::Error>
        where
            __D: near_sdk::serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            enum __Field {
                __field0,
                __field1,
                __field2,
                __field3,
                __field4,
                __field5,
            }
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(
                        __formatter,
                        "variant identifier",
                    )
                }
                fn visit_u64<__E>(
                    self,
                    __value: u64,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private::Ok(__Field::__field0),
                        1u64 => _serde::__private::Ok(__Field::__field1),
                        2u64 => _serde::__private::Ok(__Field::__field2),
                        3u64 => _serde::__private::Ok(__Field::__field3),
                        4u64 => _serde::__private::Ok(__Field::__field4),
                        5u64 => _serde::__private::Ok(__Field::__field5),
                        _ => {
                            _serde::__private::Err(
                                _serde::de::Error::invalid_value(
                                    _serde::de::Unexpected::Unsigned(__value),
                                    &"variant index 0 <= i < 6",
                                ),
                            )
                        }
                    }
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "PauseManager" => _serde::__private::Ok(__Field::__field0),
                        "UnrestrictedUnlock" => _serde::__private::Ok(__Field::__field1),
                        "UnrestrictedLpUnlock" => {
                            _serde::__private::Ok(__Field::__field2)
                        }
                        "UnrestrictedWithdraw" => {
                            _serde::__private::Ok(__Field::__field3)
                        }
                        "WhitelistManager" => _serde::__private::Ok(__Field::__field4),
                        "ConfigManager" => _serde::__private::Ok(__Field::__field5),
                        _ => {
                            _serde::__private::Err(
                                _serde::de::Error::unknown_variant(__value, VARIANTS),
                            )
                        }
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"PauseManager" => _serde::__private::Ok(__Field::__field0),
                        b"UnrestrictedUnlock" => _serde::__private::Ok(__Field::__field1),
                        b"UnrestrictedLpUnlock" => {
                            _serde::__private::Ok(__Field::__field2)
                        }
                        b"UnrestrictedWithdraw" => {
                            _serde::__private::Ok(__Field::__field3)
                        }
                        b"WhitelistManager" => _serde::__private::Ok(__Field::__field4),
                        b"ConfigManager" => _serde::__private::Ok(__Field::__field5),
                        _ => {
                            let __value = &_serde::__private::from_utf8_lossy(__value);
                            _serde::__private::Err(
                                _serde::de::Error::unknown_variant(__value, VARIANTS),
                            )
                        }
                    }
                }
            }
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(
                        __deserializer,
                        __FieldVisitor,
                    )
                }
            }
            struct __Visitor<'de> {
                marker: _serde::__private::PhantomData<Role>,
                lifetime: _serde::__private::PhantomData<&'de ()>,
            }
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = Role;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "enum Role")
                }
                fn visit_enum<__A>(
                    self,
                    __data: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::EnumAccess<'de>,
                {
                    match match _serde::de::EnumAccess::variant(__data) {
                        _serde::__private::Ok(__val) => __val,
                        _serde::__private::Err(__err) => {
                            return _serde::__private::Err(__err);
                        }
                    } {
                        (__Field::__field0, __variant) => {
                            match _serde::de::VariantAccess::unit_variant(__variant) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::__private::Ok(Role::PauseManager)
                        }
                        (__Field::__field1, __variant) => {
                            match _serde::de::VariantAccess::unit_variant(__variant) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::__private::Ok(Role::UnrestrictedUnlock)
                        }
                        (__Field::__field2, __variant) => {
                            match _serde::de::VariantAccess::unit_variant(__variant) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::__private::Ok(Role::UnrestrictedLpUnlock)
                        }
                        (__Field::__field3, __variant) => {
                            match _serde::de::VariantAccess::unit_variant(__variant) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::__private::Ok(Role::UnrestrictedWithdraw)
                        }
                        (__Field::__field4, __variant) => {
                            match _serde::de::VariantAccess::unit_variant(__variant) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::__private::Ok(Role::WhitelistManager)
                        }
                        (__Field::__field5, __variant) => {
                            match _serde::de::VariantAccess::unit_variant(__variant) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                            _serde::__private::Ok(Role::ConfigManager)
                        }
                    }
                }
            }
            const VARIANTS: &'static [&'static str] = &[
                "PauseManager",
                "UnrestrictedUnlock",
                "UnrestrictedLpUnlock",
                "UnrestrictedWithdraw",
                "WhitelistManager",
                "ConfigManager",
            ];
            _serde::Deserializer::deserialize_enum(
                __deserializer,
                "Role",
                VARIANTS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<Role>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    use near_sdk::serde as _serde;
    #[automatically_derived]
    impl near_sdk::serde::Serialize for Role {
        fn serialize<__S>(
            &self,
            __serializer: __S,
        ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: near_sdk::serde::Serializer,
        {
            match *self {
                Role::PauseManager => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "Role",
                        0u32,
                        "PauseManager",
                    )
                }
                Role::UnrestrictedUnlock => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "Role",
                        1u32,
                        "UnrestrictedUnlock",
                    )
                }
                Role::UnrestrictedLpUnlock => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "Role",
                        2u32,
                        "UnrestrictedLpUnlock",
                    )
                }
                Role::UnrestrictedWithdraw => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "Role",
                        3u32,
                        "UnrestrictedWithdraw",
                    )
                }
                Role::WhitelistManager => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "Role",
                        4u32,
                        "WhitelistManager",
                    )
                }
                Role::ConfigManager => {
                    _serde::Serializer::serialize_unit_variant(
                        __serializer,
                        "Role",
                        5u32,
                        "ConfigManager",
                    )
                }
            }
        }
    }
};
#[automatically_derived]
impl ::core::marker::Copy for Role {}
#[automatically_derived]
impl ::core::clone::Clone for Role {
    #[inline]
    fn clone(&self) -> Role {
        *self
    }
}
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
    __acl: __Acl,
}
impl borsh::de::BorshDeserialize for FastBridge
where
    UnorderedMap<String, (AccountId, TransferMessage)>: borsh::BorshDeserialize,
    LookupMap<AccountId, LookupMap<AccountId, u128>>: borsh::BorshDeserialize,
    u128: borsh::BorshDeserialize,
    AccountId: borsh::BorshDeserialize,
    AccountId: borsh::BorshDeserialize,
    EthAddress: borsh::BorshDeserialize,
    LockDuration: borsh::BorshDeserialize,
    Duration: borsh::BorshDeserialize,
    UnorderedMap<AccountId, WhitelistMode>: borsh::BorshDeserialize,
    UnorderedSet<String>: borsh::BorshDeserialize,
    bool: borsh::BorshDeserialize,
    UnorderedMap<AccountId, u128>: borsh::BorshDeserialize,
    __Acl: borsh::BorshDeserialize,
{
    fn deserialize(
        buf: &mut &[u8],
    ) -> ::core::result::Result<Self, borsh::maybestd::io::Error> {
        Ok(Self {
            pending_transfers: borsh::BorshDeserialize::deserialize(buf)?,
            user_balances: borsh::BorshDeserialize::deserialize(buf)?,
            nonce: borsh::BorshDeserialize::deserialize(buf)?,
            prover_account: borsh::BorshDeserialize::deserialize(buf)?,
            eth_client_account: borsh::BorshDeserialize::deserialize(buf)?,
            eth_bridge_contract: borsh::BorshDeserialize::deserialize(buf)?,
            lock_duration: borsh::BorshDeserialize::deserialize(buf)?,
            eth_block_time: borsh::BorshDeserialize::deserialize(buf)?,
            whitelist_tokens: borsh::BorshDeserialize::deserialize(buf)?,
            whitelist_accounts: borsh::BorshDeserialize::deserialize(buf)?,
            is_whitelist_mode_enabled: borsh::BorshDeserialize::deserialize(buf)?,
            pending_transfers_balances: borsh::BorshDeserialize::deserialize(buf)?,
            __acl: borsh::BorshDeserialize::deserialize(buf)?,
        })
    }
}
impl borsh::ser::BorshSerialize for FastBridge
where
    UnorderedMap<String, (AccountId, TransferMessage)>: borsh::ser::BorshSerialize,
    LookupMap<AccountId, LookupMap<AccountId, u128>>: borsh::ser::BorshSerialize,
    u128: borsh::ser::BorshSerialize,
    AccountId: borsh::ser::BorshSerialize,
    AccountId: borsh::ser::BorshSerialize,
    EthAddress: borsh::ser::BorshSerialize,
    LockDuration: borsh::ser::BorshSerialize,
    Duration: borsh::ser::BorshSerialize,
    UnorderedMap<AccountId, WhitelistMode>: borsh::ser::BorshSerialize,
    UnorderedSet<String>: borsh::ser::BorshSerialize,
    bool: borsh::ser::BorshSerialize,
    UnorderedMap<AccountId, u128>: borsh::ser::BorshSerialize,
    __Acl: borsh::ser::BorshSerialize,
{
    fn serialize<W: borsh::maybestd::io::Write>(
        &self,
        writer: &mut W,
    ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
        borsh::BorshSerialize::serialize(&self.pending_transfers, writer)?;
        borsh::BorshSerialize::serialize(&self.user_balances, writer)?;
        borsh::BorshSerialize::serialize(&self.nonce, writer)?;
        borsh::BorshSerialize::serialize(&self.prover_account, writer)?;
        borsh::BorshSerialize::serialize(&self.eth_client_account, writer)?;
        borsh::BorshSerialize::serialize(&self.eth_bridge_contract, writer)?;
        borsh::BorshSerialize::serialize(&self.lock_duration, writer)?;
        borsh::BorshSerialize::serialize(&self.eth_block_time, writer)?;
        borsh::BorshSerialize::serialize(&self.whitelist_tokens, writer)?;
        borsh::BorshSerialize::serialize(&self.whitelist_accounts, writer)?;
        borsh::BorshSerialize::serialize(&self.is_whitelist_mode_enabled, writer)?;
        borsh::BorshSerialize::serialize(&self.pending_transfers_balances, writer)?;
        borsh::BorshSerialize::serialize(&self.__acl, writer)?;
        Ok(())
    }
}
impl Default for FastBridge {
    fn default() -> Self {
        near_sdk::env::panic_str("The contract is not initialized");
    }
}
impl FastBridgeExt {
    pub fn pa_storage_key(self) -> near_sdk::Promise {
        let __args = ::alloc::vec::Vec::new();
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "pa_storage_key".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn pa_is_paused(self, key: String) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                key: &'nearinput String,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "key",
                            &self.key,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { key: &key };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "pa_is_paused".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn pa_all_paused(self) -> near_sdk::Promise {
        let __args = ::alloc::vec::Vec::new();
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "pa_all_paused".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn pa_pause_feature(self, key: String) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                key: &'nearinput String,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "key",
                            &self.key,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { key: &key };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "pa_pause_feature".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn pa_unpause_feature(self, key: String) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                key: &'nearinput String,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "key",
                            &self.key,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { key: &key };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "pa_unpause_feature".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
}
impl Pausable for FastBridge {
    fn pa_storage_key(&self) -> Vec<u8> {
        ("__PAUSE__").as_bytes().to_vec()
    }
    fn pa_is_paused(&self, key: String) -> bool {
        self.pa_all_paused()
            .map(|keys| keys.contains(&key) || keys.contains("ALL"))
            .unwrap_or(false)
    }
    fn pa_all_paused(&self) -> Option<std::collections::HashSet<String>> {
        ::near_sdk::env::storage_read(self.pa_storage_key().as_ref())
            .map(|value| {
                std::collections::HashSet::try_from_slice(value.as_ref())
                    .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                        "Pausable: Invalid format for paused keys",
                    ))
            })
    }
    fn pa_pause_feature(&mut self, key: String) {
        let __acl_any_roles: Vec<&str> = <[_]>::into_vec(
            #[rustc_box]
            ::alloc::boxed::Box::new([Role::PauseManager.into()]),
        );
        let __acl_any_roles_ser: Vec<String> = __acl_any_roles
            .iter()
            .map(|&role| role.into())
            .collect();
        let __acl_any_account_id = ::near_sdk::env::predecessor_account_id();
        if !self.acl_has_any_role(__acl_any_roles_ser, __acl_any_account_id) {
            let message = {
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &[
                            "Insufficient permissions for method ",
                            " restricted by access control. Requires one of these roles: ",
                        ],
                        &[
                            ::core::fmt::ArgumentV1::new_display(&"pa_pause_feature"),
                            ::core::fmt::ArgumentV1::new_debug(&__acl_any_roles),
                        ],
                    ),
                );
                res
            };
            near_sdk::env::panic_str(&message);
        }
        let mut paused_keys = self.pa_all_paused().unwrap_or_default();
        paused_keys.insert(key.clone());
        ::near_sdk::env::log_str(
            near_plugins::events::AsEvent::event(
                    &near_plugins::pausable::Pause {
                        by: ::near_sdk::env::predecessor_account_id(),
                        key,
                    },
                )
                .as_ref(),
        );
        ::near_sdk::env::storage_write(
            self.pa_storage_key().as_ref(),
            paused_keys
                .try_to_vec()
                .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                    "Pausable: Unexpected error serializing keys",
                ))
                .as_ref(),
        );
    }
    fn pa_unpause_feature(&mut self, key: String) {
        let __acl_any_roles: Vec<&str> = <[_]>::into_vec(
            #[rustc_box]
            ::alloc::boxed::Box::new([Role::PauseManager.into()]),
        );
        let __acl_any_roles_ser: Vec<String> = __acl_any_roles
            .iter()
            .map(|&role| role.into())
            .collect();
        let __acl_any_account_id = ::near_sdk::env::predecessor_account_id();
        if !self.acl_has_any_role(__acl_any_roles_ser, __acl_any_account_id) {
            let message = {
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &[
                            "Insufficient permissions for method ",
                            " restricted by access control. Requires one of these roles: ",
                        ],
                        &[
                            ::core::fmt::ArgumentV1::new_display(&"pa_unpause_feature"),
                            ::core::fmt::ArgumentV1::new_debug(&__acl_any_roles),
                        ],
                    ),
                );
                res
            };
            near_sdk::env::panic_str(&message);
        }
        let mut paused_keys = self.pa_all_paused().unwrap_or_default();
        paused_keys.remove(&key);
        ::near_sdk::env::log_str(
            near_plugins::events::AsEvent::event(
                    &near_plugins::pausable::Unpause {
                        by: ::near_sdk::env::predecessor_account_id(),
                        key,
                    },
                )
                .as_ref(),
        );
        if paused_keys.is_empty() {
            ::near_sdk::env::storage_remove(self.pa_storage_key().as_ref());
        } else {
            ::near_sdk::env::storage_write(
                self.pa_storage_key().as_ref(),
                paused_keys
                    .try_to_vec()
                    .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                        "Pausable: Unexpected error serializing keys",
                    ))
                    .as_ref(),
            );
        }
    }
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn pa_storage_key() {
    near_sdk::env::setup_panic_hook();
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.pa_storage_key();
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn pa_is_paused() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        key: String,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "key" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"key" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { key: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("key"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("key") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { key: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["key"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { key }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.pa_is_paused(key);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn pa_all_paused() {
    near_sdk::env::setup_panic_hook();
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.pa_all_paused();
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn pa_pause_feature() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method pa_pause_feature doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        key: String,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "key" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"key" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { key: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("key"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("key") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { key: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["key"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { key }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    contract.pa_pause_feature(key);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn pa_unpause_feature() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method pa_unpause_feature doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        key: String,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "key" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"key" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { key: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("key"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("key") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { key: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["key"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { key }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    contract.pa_unpause_feature(key);
    near_sdk::env::state_write(&contract);
}
#[must_use]
pub struct FastBridgeExt {
    pub(crate) account_id: near_sdk::AccountId,
    pub(crate) deposit: near_sdk::Balance,
    pub(crate) static_gas: near_sdk::Gas,
    pub(crate) gas_weight: near_sdk::GasWeight,
}
impl FastBridgeExt {
    pub fn with_attached_deposit(mut self, amount: near_sdk::Balance) -> Self {
        self.deposit = amount;
        self
    }
    pub fn with_static_gas(mut self, static_gas: near_sdk::Gas) -> Self {
        self.static_gas = static_gas;
        self
    }
    pub fn with_unused_gas_weight(mut self, gas_weight: u64) -> Self {
        self.gas_weight = near_sdk::GasWeight(gas_weight);
        self
    }
}
impl FastBridge {
    /// API for calling this contract's functions in a subsequent execution.
    pub fn ext(account_id: near_sdk::AccountId) -> FastBridgeExt {
        FastBridgeExt {
            account_id,
            deposit: 0,
            static_gas: near_sdk::Gas(0),
            gas_weight: near_sdk::GasWeight::default(),
        }
    }
}
struct __Acl {
    /// Stores permissions per account.
    permissions: ::near_sdk::store::UnorderedMap<::near_sdk::AccountId, RoleFlags>,
    /// Stores the set of accounts that bear a permission.
    bearers: ::near_sdk::store::UnorderedMap<
        RoleFlags,
        ::near_sdk::store::UnorderedSet<::near_sdk::AccountId>,
    >,
}
impl borsh::de::BorshDeserialize for __Acl
where
    ::near_sdk::store::UnorderedMap<
        ::near_sdk::AccountId,
        RoleFlags,
    >: borsh::BorshDeserialize,
    ::near_sdk::store::UnorderedMap<
        RoleFlags,
        ::near_sdk::store::UnorderedSet<::near_sdk::AccountId>,
    >: borsh::BorshDeserialize,
{
    fn deserialize(
        buf: &mut &[u8],
    ) -> ::core::result::Result<Self, borsh::maybestd::io::Error> {
        Ok(Self {
            permissions: borsh::BorshDeserialize::deserialize(buf)?,
            bearers: borsh::BorshDeserialize::deserialize(buf)?,
        })
    }
}
impl borsh::ser::BorshSerialize for __Acl
where
    ::near_sdk::store::UnorderedMap<
        ::near_sdk::AccountId,
        RoleFlags,
    >: borsh::ser::BorshSerialize,
    ::near_sdk::store::UnorderedMap<
        RoleFlags,
        ::near_sdk::store::UnorderedSet<::near_sdk::AccountId>,
    >: borsh::ser::BorshSerialize,
{
    fn serialize<W: borsh::maybestd::io::Write>(
        &self,
        writer: &mut W,
    ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
        borsh::BorshSerialize::serialize(&self.permissions, writer)?;
        borsh::BorshSerialize::serialize(&self.bearers, writer)?;
        Ok(())
    }
}
impl Default for __Acl {
    fn default() -> Self {
        let base_prefix = <FastBridge as AccessControllable>::acl_storage_prefix();
        Self {
            permissions: ::near_sdk::store::UnorderedMap::new(
                __acl_storage_prefix(base_prefix, __AclStorageKey::Permissions),
            ),
            bearers: ::near_sdk::store::UnorderedMap::new(
                __acl_storage_prefix(base_prefix, __AclStorageKey::Bearers),
            ),
        }
    }
}
/// Used to make storage prefixes unique. Not to be used directly,
/// instead it should be prepended to the storage prefix specified by
/// the user.
enum __AclStorageKey {
    Permissions,
    Bearers,
    BearersSet { permission: RoleFlags },
}
impl borsh::ser::BorshSerialize for __AclStorageKey
where
    RoleFlags: borsh::ser::BorshSerialize,
{
    fn serialize<W: borsh::maybestd::io::Write>(
        &self,
        writer: &mut W,
    ) -> core::result::Result<(), borsh::maybestd::io::Error> {
        let variant_idx: u8 = match self {
            __AclStorageKey::Permissions => 0u8,
            __AclStorageKey::Bearers => 1u8,
            __AclStorageKey::BearersSet { .. } => 2u8,
        };
        writer.write_all(&variant_idx.to_le_bytes())?;
        match self {
            __AclStorageKey::Permissions => {}
            __AclStorageKey::Bearers => {}
            __AclStorageKey::BearersSet { permission } => {
                borsh::BorshSerialize::serialize(permission, writer)?;
            }
        }
        Ok(())
    }
}
/// Generates a prefix by concatenating the input parameters.
fn __acl_storage_prefix(base: &[u8], specifier: __AclStorageKey) -> Vec<u8> {
    let specifier = specifier
        .try_to_vec()
        .unwrap_or_else(|_| ::near_sdk::env::panic_str(
            "Storage key should be serializable",
        ));
    [base, specifier.as_slice()].concat()
}
impl __Acl {
    fn new_bearers_set(
        permission: RoleFlags,
    ) -> ::near_sdk::store::UnorderedSet<::near_sdk::AccountId> {
        let base_prefix = <FastBridge as AccessControllable>::acl_storage_prefix();
        let specifier = __AclStorageKey::BearersSet {
            permission,
        };
        ::near_sdk::store::UnorderedSet::new(
            __acl_storage_prefix(base_prefix, specifier),
        )
    }
    fn get_or_insert_permissions(
        &mut self,
        account_id: ::near_sdk::AccountId,
    ) -> &mut RoleFlags {
        self.permissions.entry(account_id).or_insert_with(|| RoleFlags::empty())
    }
    fn init_super_admin(&mut self, account_id: &::near_sdk::AccountId) -> bool {
        let flag = <RoleFlags>::from_bits(<Role>::acl_super_admin_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        let number_super_admins = match self.bearers.get(&flag) {
            None => 0,
            Some(bearers) => bearers.len(),
        };
        if number_super_admins > 0 {
            return false;
        }
        let res = self.add_super_admin_unchecked(account_id);
        if true {
            let msg: &str = &"Failed to init super-admin.";
            if !res {
                ::core::panicking::panic_display(&msg)
            }
        } else if !res {
            ::near_sdk::env::panic_str(&"Failed to init super-admin.")
        }
        res
    }
    /// Makes `account_id` a super-admin __without__ checking any permissions.
    /// It returns whether `account_id` is a new super-admin.
    ///
    /// Note that there may be zero or more super-admins.
    fn add_super_admin_unchecked(&mut self, account_id: &::near_sdk::AccountId) -> bool {
        let flag = <RoleFlags>::from_bits(<Role>::acl_super_admin_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        let mut permissions = self.get_or_insert_permissions(account_id.clone());
        let is_new_super_admin = !permissions.contains(flag);
        if is_new_super_admin {
            permissions.insert(flag);
            self.add_bearer(flag, account_id);
            let event = near_plugins::access_controllable::events::SuperAdminAdded {
                account: account_id.clone(),
                by: ::near_sdk::env::predecessor_account_id(),
            };
            near_plugins::events::AsEvent::emit(&event);
        }
        is_new_super_admin
    }
    fn is_super_admin(&self, account_id: &::near_sdk::AccountId) -> bool {
        let permissions = {
            match self.permissions.get(account_id) {
                Some(permissions) => permissions,
                None => return false,
            }
        };
        let super_admin = <RoleFlags>::from_bits(<Role>::acl_super_admin_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        permissions.contains(super_admin)
    }
    /// Revokes super-admin permissions from `account_id` without checking any
    /// permissions. It returns whether `account_id` was a super-admin.
    fn revoke_super_admin_unchecked(
        &mut self,
        account_id: &::near_sdk::AccountId,
    ) -> bool {
        let flag = <RoleFlags>::from_bits(<Role>::acl_super_admin_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        let mut permissions = match self.permissions.get_mut(account_id) {
            Some(permissions) => permissions,
            None => return false,
        };
        let was_super_admin = permissions.contains(flag);
        if was_super_admin {
            permissions.remove(flag);
            self.remove_bearer(flag, account_id);
            let event = near_plugins::access_controllable::events::SuperAdminRevoked {
                account: account_id.clone(),
                by: ::near_sdk::env::predecessor_account_id(),
            };
            near_plugins::events::AsEvent::emit(&event);
        }
        was_super_admin
    }
    fn add_admin(
        &mut self,
        role: Role,
        account_id: &::near_sdk::AccountId,
    ) -> Option<bool> {
        if !self.is_admin(role, &::near_sdk::env::predecessor_account_id()) {
            return None;
        }
        Some(self.add_admin_unchecked(role, account_id))
    }
    /// Makes `account_id` an admin for role, __without__ checking any
    /// permissions. Returns whether `account_id` is a new admin for `role`.
    ///
    /// Note that any role may have multiple (or zero) admins.
    fn add_admin_unchecked(
        &mut self,
        role: Role,
        account_id: &::near_sdk::AccountId,
    ) -> bool {
        let flag = <RoleFlags>::from_bits(role.acl_admin_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        let mut permissions = self.get_or_insert_permissions(account_id.clone());
        let is_new_admin = !permissions.contains(flag);
        if is_new_admin {
            permissions.insert(flag);
            self.add_bearer(flag, account_id);
            let event = near_plugins::access_controllable::events::AdminAdded {
                role: role.into(),
                account: account_id.clone(),
                by: ::near_sdk::env::predecessor_account_id(),
            };
            near_plugins::events::AsEvent::emit(&event);
        }
        is_new_admin
    }
    fn is_admin(&self, role: Role, account_id: &::near_sdk::AccountId) -> bool {
        let permissions = {
            match self.permissions.get(account_id) {
                Some(permissions) => permissions,
                None => return false,
            }
        };
        let super_admin = <RoleFlags>::from_bits(<Role>::acl_super_admin_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        let role_admin = <RoleFlags>::from_bits(role.acl_admin_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        permissions.contains(super_admin) || permissions.contains(role_admin)
    }
    fn revoke_admin(
        &mut self,
        role: Role,
        account_id: &::near_sdk::AccountId,
    ) -> Option<bool> {
        if !self.is_admin(role, &::near_sdk::env::predecessor_account_id()) {
            return None;
        }
        Some(self.revoke_admin_unchecked(role, account_id))
    }
    fn renounce_admin(&mut self, role: Role) -> bool {
        self.revoke_admin_unchecked(role, &::near_sdk::env::predecessor_account_id())
    }
    /// Revokes admin permissions from `account_id` __without__ checking any
    /// permissions. Returns whether `account_id` was an admin for `role`.
    fn revoke_admin_unchecked(
        &mut self,
        role: Role,
        account_id: &::near_sdk::AccountId,
    ) -> bool {
        let flag = <RoleFlags>::from_bits(role.acl_admin_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        let mut permissions = match self.permissions.get_mut(account_id) {
            Some(permissions) => permissions,
            None => return false,
        };
        let was_admin = permissions.contains(flag);
        if was_admin {
            permissions.remove(flag);
            self.remove_bearer(flag, account_id);
            let event = near_plugins::access_controllable::events::AdminRevoked {
                role: role.into(),
                account: account_id.clone(),
                by: ::near_sdk::env::predecessor_account_id(),
            };
            near_plugins::events::AsEvent::emit(&event);
        }
        was_admin
    }
    fn grant_role(
        &mut self,
        role: Role,
        account_id: &::near_sdk::AccountId,
    ) -> Option<bool> {
        if !self.is_admin(role, &::near_sdk::env::predecessor_account_id()) {
            return None;
        }
        Some(self.grant_role_unchecked(role, account_id))
    }
    /// Grants `role` to `account_id` __without__ checking any permissions.
    /// Returns whether `role` was newly granted to `account_id`.
    fn grant_role_unchecked(
        &mut self,
        role: Role,
        account_id: &::near_sdk::AccountId,
    ) -> bool {
        let flag = <RoleFlags>::from_bits(role.acl_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        let mut permissions = self.get_or_insert_permissions(account_id.clone());
        let is_new_grantee = !permissions.contains(flag);
        if is_new_grantee {
            permissions.insert(flag);
            self.add_bearer(flag, account_id);
            let event = near_plugins::access_controllable::events::RoleGranted {
                role: role.into(),
                by: ::near_sdk::env::predecessor_account_id(),
                to: account_id.clone(),
            };
            near_plugins::events::AsEvent::emit(&event);
        }
        is_new_grantee
    }
    fn revoke_role(
        &mut self,
        role: Role,
        account_id: &::near_sdk::AccountId,
    ) -> Option<bool> {
        if !self.is_admin(role, &::near_sdk::env::predecessor_account_id()) {
            return None;
        }
        Some(self.revoke_role_unchecked(role, account_id))
    }
    fn renounce_role(&mut self, role: Role) -> bool {
        self.revoke_role_unchecked(role, &::near_sdk::env::predecessor_account_id())
    }
    fn revoke_role_unchecked(
        &mut self,
        role: Role,
        account_id: &::near_sdk::AccountId,
    ) -> bool {
        let flag = <RoleFlags>::from_bits(role.acl_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        let mut permissions = match self.permissions.get_mut(account_id) {
            Some(permissions) => permissions,
            None => return false,
        };
        let was_grantee = permissions.contains(flag);
        if was_grantee {
            permissions.remove(flag);
            self.remove_bearer(flag, account_id);
            let event = near_plugins::access_controllable::events::RoleRevoked {
                role: role.into(),
                from: account_id.clone(),
                by: ::near_sdk::env::predecessor_account_id(),
            };
            near_plugins::events::AsEvent::emit(&event);
        }
        was_grantee
    }
    fn has_role(&self, role: Role, account_id: &::near_sdk::AccountId) -> bool {
        match self.permissions.get(account_id) {
            Some(permissions) => {
                let flag = <RoleFlags>::from_bits(role.acl_permission())
                    .unwrap_or_else(|| ::near_sdk::env::panic_str(
                        "Value does not correspond to a permission",
                    ));
                permissions.contains(flag)
            }
            None => false,
        }
    }
    fn has_any_role(
        &self,
        roles: Vec<Role>,
        account_id: &::near_sdk::AccountId,
    ) -> bool {
        let target = roles
            .iter()
            .map(|role| {
                <RoleFlags>::from_bits(role.acl_permission())
                    .unwrap_or_else(|| ::near_sdk::env::panic_str(
                        "Value does not correspond to a permission",
                    ))
            })
            .fold(<RoleFlags>::empty(), |acc, x| acc | x);
        self.has_any_permission(target, account_id)
    }
    fn has_any_permission(
        &self,
        target: RoleFlags,
        account_id: &::near_sdk::AccountId,
    ) -> bool {
        let permissions = match self.permissions.get(account_id) {
            Some(&permissions) => permissions,
            None => return false,
        };
        target.intersects(permissions)
    }
    /// Adds `account_id` to the set of `permission` bearers.
    ///
    /// # Panics
    ///
    /// Panics if `permission` has more than one active bit. The type of
    /// permission defines only flags which have one active bit. Still,
    /// developers might call this function with a `permission` that has
    /// multiple active bits. In that case, the panic prevents polluting
    /// state.
    fn add_bearer(&mut self, permission: RoleFlags, account_id: &::near_sdk::AccountId) {
        if true {
            let msg: &str = &"Adding a bearer is allowed only for permissions with exactly one active bit";
            if !permission.bits().is_power_of_two() {
                ::core::panicking::panic_display(&msg)
            }
        } else if !permission.bits().is_power_of_two() {
            ::near_sdk::env::panic_str(
                &"Adding a bearer is allowed only for permissions with exactly one active bit",
            )
        }
        let mut set = self
            .bearers
            .entry(permission)
            .or_insert_with(|| { Self::new_bearers_set(permission) });
        set.insert(account_id.clone());
    }
    /// Enables paginated retrieval of bearers. Returns up to `limit`
    /// bearers of `permission`, skipping the first `skip` items.
    ///
    /// # Panics
    ///
    /// Panics if `skip` or `limit` are outside the range of `usize`.
    fn get_bearers(
        &self,
        permission: RoleFlags,
        skip: u64,
        limit: u64,
    ) -> Vec<::near_sdk::AccountId> {
        let skip: usize = ::std::convert::TryFrom::try_from(skip)
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "skip should be in the range of usize",
            ));
        let limit: usize = ::std::convert::TryFrom::try_from(limit)
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "limit should be in the range of usize",
            ));
        let set = match self.bearers.get(&permission) {
            Some(set) => set,
            None => return ::alloc::vec::Vec::new(),
        };
        set.iter().skip(skip).take(limit).cloned().collect()
    }
    /// Removes `account_id` from the set of `permission` bearers.
    fn remove_bearer(
        &mut self,
        permission: RoleFlags,
        account_id: &::near_sdk::AccountId,
    ) {
        let mut set = match self.bearers.get_mut(&permission) {
            Some(set) => set,
            None => return,
        };
        set.remove(account_id);
    }
}
impl FastBridgeExt {
    pub fn acl_storage_prefix(self) -> near_sdk::Promise {
        let __args = ::alloc::vec::Vec::new();
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_storage_prefix".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_init_super_admin(
        self,
        account_id: ::near_sdk::AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                account_id: &'nearinput ::near_sdk::AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "account_id",
                            &self.account_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { account_id: &account_id };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_init_super_admin".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_is_super_admin(
        self,
        account_id: ::near_sdk::AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                account_id: &'nearinput ::near_sdk::AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "account_id",
                            &self.account_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { account_id: &account_id };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_is_super_admin".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_add_admin(
        self,
        role: String,
        account_id: ::near_sdk::AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                role: &'nearinput String,
                account_id: &'nearinput ::near_sdk::AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "role",
                            &self.role,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "account_id",
                            &self.account_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                role: &role,
                account_id: &account_id,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_add_admin".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_is_admin(
        self,
        role: String,
        account_id: ::near_sdk::AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                role: &'nearinput String,
                account_id: &'nearinput ::near_sdk::AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "role",
                            &self.role,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "account_id",
                            &self.account_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                role: &role,
                account_id: &account_id,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_is_admin".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_revoke_admin(
        self,
        role: String,
        account_id: ::near_sdk::AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                role: &'nearinput String,
                account_id: &'nearinput ::near_sdk::AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "role",
                            &self.role,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "account_id",
                            &self.account_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                role: &role,
                account_id: &account_id,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_revoke_admin".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_renounce_admin(self, role: String) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                role: &'nearinput String,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "role",
                            &self.role,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { role: &role };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_renounce_admin".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_revoke_role(
        self,
        role: String,
        account_id: ::near_sdk::AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                role: &'nearinput String,
                account_id: &'nearinput ::near_sdk::AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "role",
                            &self.role,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "account_id",
                            &self.account_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                role: &role,
                account_id: &account_id,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_revoke_role".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_renounce_role(self, role: String) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                role: &'nearinput String,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "role",
                            &self.role,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { role: &role };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_renounce_role".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_grant_role(
        self,
        role: String,
        account_id: ::near_sdk::AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                role: &'nearinput String,
                account_id: &'nearinput ::near_sdk::AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "role",
                            &self.role,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "account_id",
                            &self.account_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                role: &role,
                account_id: &account_id,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_grant_role".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_has_role(
        self,
        role: String,
        account_id: ::near_sdk::AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                role: &'nearinput String,
                account_id: &'nearinput ::near_sdk::AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "role",
                            &self.role,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "account_id",
                            &self.account_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                role: &role,
                account_id: &account_id,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_has_role".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_has_any_role(
        self,
        roles: Vec<String>,
        account_id: ::near_sdk::AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                roles: &'nearinput Vec<String>,
                account_id: &'nearinput ::near_sdk::AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "roles",
                            &self.roles,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "account_id",
                            &self.account_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                roles: &roles,
                account_id: &account_id,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_has_any_role".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_get_super_admins(self, skip: u64, limit: u64) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                skip: &'nearinput u64,
                limit: &'nearinput u64,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "skip",
                            &self.skip,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "limit",
                            &self.limit,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                skip: &skip,
                limit: &limit,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_get_super_admins".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_get_admins(
        self,
        role: String,
        skip: u64,
        limit: u64,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                role: &'nearinput String,
                skip: &'nearinput u64,
                limit: &'nearinput u64,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "role",
                            &self.role,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "skip",
                            &self.skip,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "limit",
                            &self.limit,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                role: &role,
                skip: &skip,
                limit: &limit,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_get_admins".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn acl_get_grantees(
        self,
        role: String,
        skip: u64,
        limit: u64,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                role: &'nearinput String,
                skip: &'nearinput u64,
                limit: &'nearinput u64,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "role",
                            &self.role,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "skip",
                            &self.skip,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "limit",
                            &self.limit,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                role: &role,
                skip: &skip,
                limit: &limit,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "acl_get_grantees".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
}
impl AccessControllable for FastBridge {
    fn acl_storage_prefix() -> &'static [u8] {
        ("__acl").as_bytes()
    }
    fn acl_init_super_admin(&mut self, account_id: ::near_sdk::AccountId) -> bool {
        self.__acl.init_super_admin(&account_id)
    }
    fn acl_is_super_admin(&self, account_id: ::near_sdk::AccountId) -> bool {
        self.__acl.is_super_admin(&account_id)
    }
    fn acl_add_admin(
        &mut self,
        role: String,
        account_id: ::near_sdk::AccountId,
    ) -> Option<bool> {
        let role: Role = ::std::convert::TryFrom::try_from(role.as_str())
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "Value does not correspond to a role",
            ));
        self.__acl.add_admin(role, &account_id)
    }
    fn acl_is_admin(&self, role: String, account_id: ::near_sdk::AccountId) -> bool {
        let role: Role = ::std::convert::TryFrom::try_from(role.as_str())
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "Value does not correspond to a role",
            ));
        self.__acl.is_admin(role, &account_id)
    }
    fn acl_revoke_admin(
        &mut self,
        role: String,
        account_id: ::near_sdk::AccountId,
    ) -> Option<bool> {
        let role: Role = ::std::convert::TryFrom::try_from(role.as_str())
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "Value does not correspond to a role",
            ));
        self.__acl.revoke_admin(role, &account_id)
    }
    fn acl_renounce_admin(&mut self, role: String) -> bool {
        let role: Role = ::std::convert::TryFrom::try_from(role.as_str())
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "Value does not correspond to a role",
            ));
        self.__acl.renounce_admin(role)
    }
    fn acl_revoke_role(
        &mut self,
        role: String,
        account_id: ::near_sdk::AccountId,
    ) -> Option<bool> {
        let role: Role = ::std::convert::TryFrom::try_from(role.as_str())
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "Value does not correspond to a role",
            ));
        self.__acl.revoke_role(role, &account_id)
    }
    fn acl_renounce_role(&mut self, role: String) -> bool {
        let role: Role = ::std::convert::TryFrom::try_from(role.as_str())
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "Value does not correspond to a role",
            ));
        self.__acl.renounce_role(role)
    }
    fn acl_grant_role(
        &mut self,
        role: String,
        account_id: ::near_sdk::AccountId,
    ) -> Option<bool> {
        let role: Role = ::std::convert::TryFrom::try_from(role.as_str())
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "Value does not correspond to a role",
            ));
        self.__acl.grant_role(role, &account_id)
    }
    fn acl_has_role(&self, role: String, account_id: ::near_sdk::AccountId) -> bool {
        let role: Role = ::std::convert::TryFrom::try_from(role.as_str())
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "Value does not correspond to a role",
            ));
        self.__acl.has_role(role, &account_id)
    }
    fn acl_has_any_role(
        &self,
        roles: Vec<String>,
        account_id: ::near_sdk::AccountId,
    ) -> bool {
        let roles: Vec<Role> = roles
            .iter()
            .map(|role| {
                ::std::convert::TryFrom::try_from(role.as_str())
                    .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                        "Value does not correspond to a role",
                    ))
            })
            .collect();
        self.__acl.has_any_role(roles, &account_id)
    }
    fn acl_get_super_admins(&self, skip: u64, limit: u64) -> Vec<::near_sdk::AccountId> {
        let permission = <RoleFlags>::from_bits(<Role>::acl_super_admin_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        self.__acl.get_bearers(permission, skip, limit)
    }
    fn acl_get_admins(
        &self,
        role: String,
        skip: u64,
        limit: u64,
    ) -> Vec<::near_sdk::AccountId> {
        let role: Role = ::std::convert::TryFrom::try_from(role.as_str())
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "Value does not correspond to a role",
            ));
        let permission = <RoleFlags>::from_bits(role.acl_admin_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        self.__acl.get_bearers(permission, skip, limit)
    }
    fn acl_get_grantees(
        &self,
        role: String,
        skip: u64,
        limit: u64,
    ) -> Vec<::near_sdk::AccountId> {
        let role: Role = ::std::convert::TryFrom::try_from(role.as_str())
            .unwrap_or_else(|_| ::near_sdk::env::panic_str(
                "Value does not correspond to a role",
            ));
        let permission = <RoleFlags>::from_bits(role.acl_permission())
            .unwrap_or_else(|| ::near_sdk::env::panic_str(
                "Value does not correspond to a permission",
            ));
        self.__acl.get_bearers(permission, skip, limit)
    }
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_storage_prefix() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method acl_storage_prefix doesn't accept deposit");
    }
    let result = FastBridge::acl_storage_prefix();
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_init_super_admin() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::current_account_id() != near_sdk::env::predecessor_account_id() {
        near_sdk::env::panic_str("Method acl_init_super_admin is private");
    }
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method acl_init_super_admin doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        account_id: ::near_sdk::AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "account_id" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"account_id" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            ::near_sdk::AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { account_id: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<
                            ::near_sdk::AccountId,
                        > = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "account_id",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            ::near_sdk::AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("account_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { account_id: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["account_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { account_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_init_super_admin(account_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_is_super_admin() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        account_id: ::near_sdk::AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "account_id" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"account_id" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            ::near_sdk::AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { account_id: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<
                            ::near_sdk::AccountId,
                        > = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "account_id",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            ::near_sdk::AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("account_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { account_id: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["account_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { account_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_is_super_admin(account_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_add_admin() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method acl_add_admin doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        role: String,
        account_id: ::near_sdk::AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "role" => _serde::__private::Ok(__Field::__field0),
                            "account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"role" => _serde::__private::Ok(__Field::__field0),
                            b"account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            ::near_sdk::AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<
                            ::near_sdk::AccountId,
                        > = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("role"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "account_id",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            ::near_sdk::AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("role") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("account_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["role", "account_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { role, account_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_add_admin(role, account_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_is_admin() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        role: String,
        account_id: ::near_sdk::AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "role" => _serde::__private::Ok(__Field::__field0),
                            "account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"role" => _serde::__private::Ok(__Field::__field0),
                            b"account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            ::near_sdk::AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<
                            ::near_sdk::AccountId,
                        > = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("role"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "account_id",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            ::near_sdk::AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("role") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("account_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["role", "account_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { role, account_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_is_admin(role, account_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_revoke_admin() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method acl_revoke_admin doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        role: String,
        account_id: ::near_sdk::AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "role" => _serde::__private::Ok(__Field::__field0),
                            "account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"role" => _serde::__private::Ok(__Field::__field0),
                            b"account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            ::near_sdk::AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<
                            ::near_sdk::AccountId,
                        > = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("role"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "account_id",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            ::near_sdk::AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("role") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("account_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["role", "account_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { role, account_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_revoke_admin(role, account_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_renounce_admin() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method acl_renounce_admin doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        role: String,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "role" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"role" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { role: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("role"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("role") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { role: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["role"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { role }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_renounce_admin(role);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_revoke_role() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method acl_revoke_role doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        role: String,
        account_id: ::near_sdk::AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "role" => _serde::__private::Ok(__Field::__field0),
                            "account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"role" => _serde::__private::Ok(__Field::__field0),
                            b"account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            ::near_sdk::AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<
                            ::near_sdk::AccountId,
                        > = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("role"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "account_id",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            ::near_sdk::AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("role") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("account_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["role", "account_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { role, account_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_revoke_role(role, account_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_renounce_role() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method acl_renounce_role doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        role: String,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "role" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"role" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { role: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("role"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("role") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { role: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["role"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { role }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_renounce_role(role);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_grant_role() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method acl_grant_role doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        role: String,
        account_id: ::near_sdk::AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "role" => _serde::__private::Ok(__Field::__field0),
                            "account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"role" => _serde::__private::Ok(__Field::__field0),
                            b"account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            ::near_sdk::AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<
                            ::near_sdk::AccountId,
                        > = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("role"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "account_id",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            ::near_sdk::AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("role") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("account_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["role", "account_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { role, account_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_grant_role(role, account_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_has_role() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        role: String,
        account_id: ::near_sdk::AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "role" => _serde::__private::Ok(__Field::__field0),
                            "account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"role" => _serde::__private::Ok(__Field::__field0),
                            b"account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            ::near_sdk::AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<
                            ::near_sdk::AccountId,
                        > = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("role"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "account_id",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            ::near_sdk::AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("role") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("account_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            account_id: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["role", "account_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { role, account_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_has_role(role, account_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_has_any_role() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        roles: Vec<String>,
        account_id: ::near_sdk::AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "roles" => _serde::__private::Ok(__Field::__field0),
                            "account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"roles" => _serde::__private::Ok(__Field::__field0),
                            b"account_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            Vec<String>,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            ::near_sdk::AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            roles: __field0,
                            account_id: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<Vec<String>> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<
                            ::near_sdk::AccountId,
                        > = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("roles"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            Vec<String>,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "account_id",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            ::near_sdk::AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("roles") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("account_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            roles: __field0,
                            account_id: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["roles", "account_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { roles, account_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_has_any_role(roles, account_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_get_super_admins() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        skip: u64,
        limit: u64,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "skip" => _serde::__private::Ok(__Field::__field0),
                            "limit" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"skip" => _serde::__private::Ok(__Field::__field0),
                            b"limit" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            u64,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            u64,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            skip: __field0,
                            limit: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<u64> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<u64> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("skip"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<u64>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("limit"),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<u64>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("skip") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("limit") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            skip: __field0,
                            limit: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["skip", "limit"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { skip, limit }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_get_super_admins(skip, limit);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_get_admins() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        role: String,
        skip: u64,
        limit: u64,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __field2,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            2u64 => _serde::__private::Ok(__Field::__field2),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "role" => _serde::__private::Ok(__Field::__field0),
                            "skip" => _serde::__private::Ok(__Field::__field1),
                            "limit" => _serde::__private::Ok(__Field::__field2),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"role" => _serde::__private::Ok(__Field::__field0),
                            b"skip" => _serde::__private::Ok(__Field::__field1),
                            b"limit" => _serde::__private::Ok(__Field::__field2),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 3 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            u64,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 3 elements",
                                    ),
                                );
                            }
                        };
                        let __field2 = match match _serde::de::SeqAccess::next_element::<
                            u64,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        2usize,
                                        &"struct Input with 3 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            skip: __field1,
                            limit: __field2,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<u64> = _serde::__private::None;
                        let mut __field2: _serde::__private::Option<u64> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("role"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("skip"),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<u64>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field2 => {
                                    if _serde::__private::Option::is_some(&__field2) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("limit"),
                                        );
                                    }
                                    __field2 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<u64>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("role") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("skip") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field2 = match __field2 {
                            _serde::__private::Some(__field2) => __field2,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("limit") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            skip: __field1,
                            limit: __field2,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["role", "skip", "limit"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { role, skip, limit }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_get_admins(role, skip, limit);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn acl_get_grantees() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        role: String,
        skip: u64,
        limit: u64,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __field2,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            2u64 => _serde::__private::Ok(__Field::__field2),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "role" => _serde::__private::Ok(__Field::__field0),
                            "skip" => _serde::__private::Ok(__Field::__field1),
                            "limit" => _serde::__private::Ok(__Field::__field2),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"role" => _serde::__private::Ok(__Field::__field0),
                            b"skip" => _serde::__private::Ok(__Field::__field1),
                            b"limit" => _serde::__private::Ok(__Field::__field2),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 3 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            u64,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 3 elements",
                                    ),
                                );
                            }
                        };
                        let __field2 = match match _serde::de::SeqAccess::next_element::<
                            u64,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        2usize,
                                        &"struct Input with 3 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            skip: __field1,
                            limit: __field2,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<u64> = _serde::__private::None;
                        let mut __field2: _serde::__private::Option<u64> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("role"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("skip"),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<u64>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field2 => {
                                    if _serde::__private::Option::is_some(&__field2) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("limit"),
                                        );
                                    }
                                    __field2 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<u64>(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("role") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("skip") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field2 = match __field2 {
                            _serde::__private::Some(__field2) => __field2,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("limit") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            role: __field0,
                            skip: __field1,
                            limit: __field2,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["role", "skip", "limit"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { role, skip, limit }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.acl_get_grantees(role, skip, limit);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
impl FastBridgeExt {
    pub fn new(
        self,
        eth_bridge_contract: String,
        prover_account: AccountId,
        eth_client_account: AccountId,
        lock_time_min: String,
        lock_time_max: String,
        eth_block_time: Duration,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                eth_bridge_contract: &'nearinput String,
                prover_account: &'nearinput AccountId,
                eth_client_account: &'nearinput AccountId,
                lock_time_min: &'nearinput String,
                lock_time_max: &'nearinput String,
                eth_block_time: &'nearinput Duration,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1 + 1 + 1 + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "eth_bridge_contract",
                            &self.eth_bridge_contract,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "prover_account",
                            &self.prover_account,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "eth_client_account",
                            &self.eth_client_account,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "lock_time_min",
                            &self.lock_time_min,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "lock_time_max",
                            &self.lock_time_max,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "eth_block_time",
                            &self.eth_block_time,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                eth_bridge_contract: &eth_bridge_contract,
                prover_account: &prover_account,
                eth_client_account: &eth_client_account,
                lock_time_min: &lock_time_min,
                lock_time_max: &lock_time_max,
                eth_block_time: &eth_block_time,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "new".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn init_transfer(
        self,
        msg: near_sdk::json_types::Base64VecU8,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                msg: &'nearinput near_sdk::json_types::Base64VecU8,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "msg",
                            &self.msg,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { msg: &msg };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "init_transfer".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn init_transfer_callback(
        self,
        transfer_message: TransferMessage,
        sender_id: AccountId,
        update_balance: Option<UpdateBalance>,
    ) -> near_sdk::Promise {
        let __args = {
            struct Input<'nearinput> {
                transfer_message: &'nearinput TransferMessage,
                sender_id: &'nearinput AccountId,
                update_balance: &'nearinput Option<UpdateBalance>,
            }
            impl<'nearinput> borsh::ser::BorshSerialize for Input<'nearinput>
            where
                &'nearinput TransferMessage: borsh::ser::BorshSerialize,
                &'nearinput AccountId: borsh::ser::BorshSerialize,
                &'nearinput Option<UpdateBalance>: borsh::ser::BorshSerialize,
            {
                fn serialize<W: borsh::maybestd::io::Write>(
                    &self,
                    writer: &mut W,
                ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
                    borsh::BorshSerialize::serialize(&self.transfer_message, writer)?;
                    borsh::BorshSerialize::serialize(&self.sender_id, writer)?;
                    borsh::BorshSerialize::serialize(&self.update_balance, writer)?;
                    Ok(())
                }
            }
            let __args = Input {
                transfer_message: &transfer_message,
                sender_id: &sender_id,
                update_balance: &update_balance,
            };
            near_sdk::borsh::BorshSerialize::try_to_vec(&__args)
                .expect("Failed to serialize the cross contract args using Borsh.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "init_transfer_callback".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn unlock(self, nonce: U128) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                nonce: &'nearinput U128,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "nonce",
                            &self.nonce,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { nonce: &nonce };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "unlock".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn unlock_callback(
        self,
        nonce: U128,
        sender_id: AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            struct Input<'nearinput> {
                nonce: &'nearinput U128,
                sender_id: &'nearinput AccountId,
            }
            impl<'nearinput> borsh::ser::BorshSerialize for Input<'nearinput>
            where
                &'nearinput U128: borsh::ser::BorshSerialize,
                &'nearinput AccountId: borsh::ser::BorshSerialize,
            {
                fn serialize<W: borsh::maybestd::io::Write>(
                    &self,
                    writer: &mut W,
                ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
                    borsh::BorshSerialize::serialize(&self.nonce, writer)?;
                    borsh::BorshSerialize::serialize(&self.sender_id, writer)?;
                    Ok(())
                }
            }
            let __args = Input {
                nonce: &nonce,
                sender_id: &sender_id,
            };
            near_sdk::borsh::BorshSerialize::try_to_vec(&__args)
                .expect("Failed to serialize the cross contract args using Borsh.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "unlock_callback".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn lp_unlock(self, proof: Proof) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                proof: &'nearinput Proof,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "proof",
                            &self.proof,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { proof: &proof };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "lp_unlock".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn verify_log_entry_callback(
        self,
        proof: EthTransferEvent,
    ) -> near_sdk::Promise {
        let __args = {
            struct Input<'nearinput> {
                proof: &'nearinput EthTransferEvent,
            }
            impl<'nearinput> borsh::ser::BorshSerialize for Input<'nearinput>
            where
                &'nearinput EthTransferEvent: borsh::ser::BorshSerialize,
            {
                fn serialize<W: borsh::maybestd::io::Write>(
                    &self,
                    writer: &mut W,
                ) -> ::core::result::Result<(), borsh::maybestd::io::Error> {
                    borsh::BorshSerialize::serialize(&self.proof, writer)?;
                    Ok(())
                }
            }
            let __args = Input { proof: &proof };
            near_sdk::borsh::BorshSerialize::try_to_vec(&__args)
                .expect("Failed to serialize the cross contract args using Borsh.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "verify_log_entry_callback".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn get_user_balance(
        self,
        account_id: &AccountId,
        token_id: &AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                account_id: &'nearinput AccountId,
                token_id: &'nearinput AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "account_id",
                            &self.account_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "token_id",
                            &self.token_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                account_id: &account_id,
                token_id: &token_id,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "get_user_balance".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn withdraw(self, token_id: AccountId, amount: U128) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                token_id: &'nearinput AccountId,
                amount: &'nearinput U128,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "token_id",
                            &self.token_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "amount",
                            &self.amount,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                token_id: &token_id,
                amount: &amount,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "withdraw".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn withdraw_callback(
        self,
        token_id: AccountId,
        amount: U128,
        sender_id: AccountId,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                token_id: &'nearinput AccountId,
                amount: &'nearinput U128,
                sender_id: &'nearinput AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "token_id",
                            &self.token_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "amount",
                            &self.amount,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "sender_id",
                            &self.sender_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                token_id: &token_id,
                amount: &amount,
                sender_id: &sender_id,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "withdraw_callback".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn set_prover_account(self, prover_account: AccountId) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                prover_account: &'nearinput AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "prover_account",
                            &self.prover_account,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                prover_account: &prover_account,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "set_prover_account".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn set_enear_address(self, near_address: String) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                near_address: &'nearinput String,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "near_address",
                            &self.near_address,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                near_address: &near_address,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "set_enear_address".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn get_lock_duration(self) -> near_sdk::Promise {
        let __args = ::alloc::vec::Vec::new();
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "get_lock_duration".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn get_pending_balance(self, token_id: AccountId) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                token_id: &'nearinput AccountId,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "token_id",
                            &self.token_id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { token_id: &token_id };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "get_pending_balance".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn get_pending_transfers(
        self,
        from_index: usize,
        limit: usize,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                from_index: &'nearinput usize,
                limit: &'nearinput usize,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "from_index",
                            &self.from_index,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "limit",
                            &self.limit,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                from_index: &from_index,
                limit: &limit,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "get_pending_transfers".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn get_pending_transfer(self, id: String) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                id: &'nearinput String,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "id",
                            &self.id,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input { id: &id };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "get_pending_transfer".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
    pub fn set_lock_time(
        self,
        lock_time_min: String,
        lock_time_max: String,
    ) -> near_sdk::Promise {
        let __args = {
            #[serde(crate = "near_sdk::serde")]
            struct Input<'nearinput> {
                lock_time_min: &'nearinput String,
                lock_time_max: &'nearinput String,
            }
            #[doc(hidden)]
            #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
            const _: () = {
                use near_sdk::serde as _serde;
                #[automatically_derived]
                impl<'nearinput> near_sdk::serde::Serialize for Input<'nearinput> {
                    fn serialize<__S>(
                        &self,
                        __serializer: __S,
                    ) -> near_sdk::serde::__private::Result<__S::Ok, __S::Error>
                    where
                        __S: near_sdk::serde::Serializer,
                    {
                        let mut __serde_state = match _serde::Serializer::serialize_struct(
                            __serializer,
                            "Input",
                            false as usize + 1 + 1,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "lock_time_min",
                            &self.lock_time_min,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        match _serde::ser::SerializeStruct::serialize_field(
                            &mut __serde_state,
                            "lock_time_max",
                            &self.lock_time_max,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        };
                        _serde::ser::SerializeStruct::end(__serde_state)
                    }
                }
            };
            let __args = Input {
                lock_time_min: &lock_time_min,
                lock_time_max: &lock_time_max,
            };
            near_sdk::serde_json::to_vec(&__args)
                .expect("Failed to serialize the cross contract args using JSON.")
        };
        near_sdk::Promise::new(self.account_id)
            .function_call_weight(
                "set_lock_time".to_string(),
                __args,
                self.deposit,
                self.static_gas,
                self.gas_weight,
            )
    }
}
impl FastBridge {
    pub fn new(
        eth_bridge_contract: String,
        prover_account: AccountId,
        eth_client_account: AccountId,
        lock_time_min: String,
        lock_time_max: String,
        eth_block_time: Duration,
    ) -> Self {
        if true {
            let msg: &str = &"Already initialized";
            if !!env::state_exists() {
                ::core::panicking::panic_display(&msg)
            }
        } else if !!env::state_exists() {
            ::near_sdk::env::panic_str(&"Already initialized")
        }
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
        if true {
            let msg: &str = &"Error initialize: lock_time_min must be less than lock_time_max";
            if !(lock_time_max > lock_time_min) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(lock_time_max > lock_time_min) {
            ::near_sdk::env::panic_str(
                &"Error initialize: lock_time_min must be less than lock_time_max",
            )
        }
        let mut contract = Self {
            pending_transfers: UnorderedMap::new(StorageKey::PendingTransfers),
            pending_transfers_balances: UnorderedMap::new(
                StorageKey::PendingTransfersBalances,
            ),
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
        if true {
            let msg: &str = &"Failed to initialize super admin";
            if !contract.acl_init_super_admin(near_sdk::env::predecessor_account_id()) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !contract.acl_init_super_admin(near_sdk::env::predecessor_account_id())
        {
            ::near_sdk::env::panic_str(&"Failed to initialize super admin")
        }
        contract
    }
    pub fn init_transfer(
        &mut self,
        msg: near_sdk::json_types::Base64VecU8,
    ) -> PromiseOrValue<U128> {
        let mut __check_paused = true;
        let __except_roles: Vec<&str> = ::alloc::vec::Vec::new();
        let __except_roles: Vec<String> = __except_roles
            .iter()
            .map(|&x| x.into())
            .collect();
        let may_bypass = self
            .acl_has_any_role(__except_roles, ::near_sdk::env::predecessor_account_id());
        if may_bypass {
            __check_paused = false;
        }
        if __check_paused {
            if true {
                let msg: &str = &"Pausable: Method is paused";
                if !!self.pa_is_paused("init_transfer".to_string()) {
                    ::core::panicking::panic_display(&msg)
                }
            } else if !!self.pa_is_paused("init_transfer".to_string()) {
                ::near_sdk::env::panic_str(&"Pausable: Method is paused")
            }
        }
        let transfer_message = TransferMessage::try_from_slice(&msg.0)
            .unwrap_or_else(|_| env::panic_str(
                "Invalid borsh format of the `TransferMessage`",
            ));
        self.init_transfer_internal(
                transfer_message,
                env::predecessor_account_id(),
                None,
            )
            .into()
    }
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        sender_id: AccountId,
        update_balance: Option<UpdateBalance>,
    ) -> Promise {
        near_sdk::env::log_str(
            &near_sdk::serde_json::to_string(&transfer_message).unwrap(),
        );
        ext_eth_client::ext(self.eth_client_account.clone())
            .with_static_gas(utils::tera_gas(5))
            .last_block_number()
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(utils::tera_gas(200))
                    .init_transfer_callback(transfer_message, sender_id, update_balance),
            )
    }
    pub fn init_transfer_callback(
        &mut self,
        last_block_height: u64,
        transfer_message: TransferMessage,
        sender_id: AccountId,
        update_balance: Option<UpdateBalance>,
    ) -> U128 {
        if true {
            let msg: &str = &"The fee token does not match the transfer token";
            if !(transfer_message.fee.token == transfer_message.transfer.token_near) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(transfer_message.fee.token == transfer_message.transfer.token_near) {
            ::near_sdk::env::panic_str(
                &"The fee token does not match the transfer token",
            )
        }
        if let Some(update_balance) = update_balance.as_ref() {
            self.increase_balance(
                &update_balance.sender_id,
                &update_balance.token,
                &update_balance.amount.0,
            );
        }
        let mut transfer_message = transfer_message;
        let lock_period = transfer_message.valid_till - block_timestamp();
        transfer_message
            .valid_till_block_height = Some(
            last_block_height + lock_period / self.eth_block_time,
        );
        self.validate_transfer_message(&transfer_message, &sender_id);
        let user_token_balance = self
            .user_balances
            .get(&sender_id)
            .unwrap_or_else(|| {
                ::core::panicking::panic_fmt(
                    ::core::fmt::Arguments::new_v1(
                        &["Balance in ", " for user ", " not found"],
                        &[
                            ::core::fmt::ArgumentV1::new_display(
                                &transfer_message.transfer.token_near,
                            ),
                            ::core::fmt::ArgumentV1::new_display(&sender_id),
                        ],
                    ),
                )
            });
        let token_transfer_balance = user_token_balance
            .get(&transfer_message.transfer.token_near)
            .unwrap_or_else(|| {
                ::core::panicking::panic_fmt(
                    ::core::fmt::Arguments::new_v1(
                        &["Balance for token transfer: ", " not found"],
                        &[
                            ::core::fmt::ArgumentV1::new_display(
                                &&transfer_message.transfer.token_near,
                            ),
                        ],
                    ),
                )
            });
        if true {
            let msg: &str = &"Not enough transfer token balance.";
            if !(token_transfer_balance >= u128::from(transfer_message.transfer.amount))
            {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(token_transfer_balance
            >= u128::from(transfer_message.transfer.amount))
        {
            ::near_sdk::env::panic_str(&"Not enough transfer token balance.")
        }
        self.decrease_balance(
            &sender_id,
            &transfer_message.transfer.token_near,
            &u128::from(transfer_message.transfer.amount),
        );
        let token_fee_balance = user_token_balance
            .get(&transfer_message.fee.token)
            .unwrap_or_else(|| {
                ::core::panicking::panic_fmt(
                    ::core::fmt::Arguments::new_v1(
                        &["Balance for token fee: ", " not found"],
                        &[
                            ::core::fmt::ArgumentV1::new_display(
                                &&transfer_message.transfer.token_near,
                            ),
                        ],
                    ),
                )
            });
        if true {
            let msg: &str = &"Not enough fee token balance.";
            if !(token_fee_balance >= u128::from(transfer_message.fee.amount)) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(token_fee_balance >= u128::from(transfer_message.fee.amount)) {
            ::near_sdk::env::panic_str(&"Not enough fee token balance.")
        }
        self.decrease_balance(
            &sender_id,
            &transfer_message.fee.token,
            &u128::from(transfer_message.fee.amount),
        );
        let nonce = U128::from(
            self.store_transfers(sender_id.clone(), transfer_message.clone()),
        );
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
    pub fn unlock(&self, nonce: U128) -> Promise {
        let mut __check_paused = true;
        let __except_roles: Vec<&str> = <[_]>::into_vec(
            #[rustc_box]
            ::alloc::boxed::Box::new([Role::UnrestrictedUnlock.into()]),
        );
        let __except_roles: Vec<String> = __except_roles
            .iter()
            .map(|&x| x.into())
            .collect();
        let may_bypass = self
            .acl_has_any_role(__except_roles, ::near_sdk::env::predecessor_account_id());
        if may_bypass {
            __check_paused = false;
        }
        if __check_paused {
            if true {
                let msg: &str = &"Pausable: Method is paused";
                if !!self.pa_is_paused("unlock".to_string()) {
                    ::core::panicking::panic_display(&msg)
                }
            } else if !!self.pa_is_paused("unlock".to_string()) {
                ::near_sdk::env::panic_str(&"Pausable: Method is paused")
            }
        }
        ext_eth_client::ext(self.eth_client_account.clone())
            .with_static_gas(utils::tera_gas(5))
            .last_block_number()
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(utils::tera_gas(50))
                    .unlock_callback(nonce, env::predecessor_account_id()),
            )
    }
    pub fn unlock_callback(
        &mut self,
        last_block_height: u64,
        nonce: U128,
        sender_id: AccountId,
    ) {
        let transaction_id = utils::get_transaction_id(u128::try_from(nonce).unwrap());
        let (recipient_id, transfer_data) = self
            .pending_transfers
            .get(&transaction_id)
            .unwrap_or_else(|| {
                ::core::panicking::panic_fmt(
                    ::core::fmt::Arguments::new_v1(
                        &["Transaction with id: ", " not found"],
                        &[
                            ::core::fmt::ArgumentV1::new_display(
                                &&transaction_id.to_string(),
                            ),
                        ],
                    ),
                )
            });
        let is_unlock_allowed = recipient_id == sender_id
            || self.acl_has_role("UnrestrictedUnlock".to_string(), sender_id.clone());
        if true {
            let msg: &str = &{
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &["Permission denied for account: "],
                        &[::core::fmt::ArgumentV1::new_display(&sender_id)],
                    ),
                );
                res
            };
            if !is_unlock_allowed {
                ::core::panicking::panic_display(&msg)
            }
        } else if !is_unlock_allowed {
            ::near_sdk::env::panic_str(
                &{
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &["Permission denied for account: "],
                            &[::core::fmt::ArgumentV1::new_display(&sender_id)],
                        ),
                    );
                    res
                },
            )
        }
        if true {
            let msg: &str = &"Valid time is not correct.";
            if !(block_timestamp() > transfer_data.valid_till) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(block_timestamp() > transfer_data.valid_till) {
            ::near_sdk::env::panic_str(&"Valid time is not correct.")
        }
        if true {
            let msg: &str = &{
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &[
                            "Minimum allowed block height is ",
                            ", but current client\'s block height is ",
                        ],
                        &[
                            ::core::fmt::ArgumentV1::new_display(
                                &transfer_data.valid_till_block_height.unwrap(),
                            ),
                            ::core::fmt::ArgumentV1::new_display(&last_block_height),
                        ],
                    ),
                );
                res
            };
            if !(last_block_height > transfer_data.valid_till_block_height.unwrap()) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(last_block_height > transfer_data.valid_till_block_height.unwrap()) {
            ::near_sdk::env::panic_str(
                &{
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &[
                                "Minimum allowed block height is ",
                                ", but current client\'s block height is ",
                            ],
                            &[
                                ::core::fmt::ArgumentV1::new_display(
                                    &transfer_data.valid_till_block_height.unwrap(),
                                ),
                                ::core::fmt::ArgumentV1::new_display(&last_block_height),
                            ],
                        ),
                    );
                    res
                },
            )
        }
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
    pub fn lp_unlock(&mut self, proof: Proof) -> Promise {
        let mut __check_paused = true;
        let __except_roles: Vec<&str> = <[_]>::into_vec(
            #[rustc_box]
            ::alloc::boxed::Box::new([Role::UnrestrictedLpUnlock.into()]),
        );
        let __except_roles: Vec<String> = __except_roles
            .iter()
            .map(|&x| x.into())
            .collect();
        let may_bypass = self
            .acl_has_any_role(__except_roles, ::near_sdk::env::predecessor_account_id());
        if may_bypass {
            __check_paused = false;
        }
        if __check_paused {
            if true {
                let msg: &str = &"Pausable: Method is paused";
                if !!self.pa_is_paused("lp_unlock".to_string()) {
                    ::core::panicking::panic_display(&msg)
                }
            } else if !!self.pa_is_paused("lp_unlock".to_string()) {
                ::near_sdk::env::panic_str(&"Pausable: Method is paused")
            }
        }
        let parsed_proof = lp_relayer::EthTransferEvent::parse(proof.clone());
        match (&parsed_proof.eth_bridge_contract, &self.eth_bridge_contract) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    let kind = ::core::panicking::AssertKind::Eq;
                    ::core::panicking::assert_failed(
                        kind,
                        &*left_val,
                        &*right_val,
                        ::core::option::Option::Some(
                            ::core::fmt::Arguments::new_v1(
                                &[
                                    "Event\'s address ",
                                    " does not match the eth bridge address ",
                                ],
                                &[
                                    ::core::fmt::ArgumentV1::new_display(
                                        &hex::encode(parsed_proof.eth_bridge_contract),
                                    ),
                                    ::core::fmt::ArgumentV1::new_display(
                                        &hex::encode(self.eth_bridge_contract),
                                    ),
                                ],
                            ),
                        ),
                    );
                }
            }
        };
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
    pub fn verify_log_entry_callback(
        &mut self,
        verification_success: bool,
        proof: EthTransferEvent,
    ) {
        if true {
            let msg: &str = &"Failed to verify the proof";
            if !verification_success {
                ::core::panicking::panic_display(&msg)
            }
        } else if !verification_success {
            ::near_sdk::env::panic_str(&"Failed to verify the proof")
        }
        let transaction_id = utils::get_transaction_id(proof.nonce);
        let transfer = self
            .pending_transfers
            .get(&transaction_id)
            .unwrap_or_else(|| {
                ::core::panicking::panic_fmt(
                    ::core::fmt::Arguments::new_v1(
                        &["Transaction with id: ", " not found"],
                        &[
                            ::core::fmt::ArgumentV1::new_display(
                                &&transaction_id.to_string(),
                            ),
                        ],
                    ),
                )
            });
        let transfer_data = transfer.1;
        if true {
            let msg: &str = &{
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &["Wrong recipient ", ", expected "],
                        &[
                            ::core::fmt::ArgumentV1::new_debug(&proof.recipient),
                            ::core::fmt::ArgumentV1::new_debug(&transfer_data.recipient),
                        ],
                    ),
                );
                res
            };
            if !(proof.recipient == transfer_data.recipient) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(proof.recipient == transfer_data.recipient) {
            ::near_sdk::env::panic_str(
                &{
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &["Wrong recipient ", ", expected "],
                            &[
                                ::core::fmt::ArgumentV1::new_debug(&proof.recipient),
                                ::core::fmt::ArgumentV1::new_debug(&transfer_data.recipient),
                            ],
                        ),
                    );
                    res
                },
            )
        }
        if true {
            let msg: &str = &{
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &["Wrong token transferred ", ", expected "],
                        &[
                            ::core::fmt::ArgumentV1::new_debug(&proof.token),
                            ::core::fmt::ArgumentV1::new_debug(
                                &transfer_data.transfer.token_eth,
                            ),
                        ],
                    ),
                );
                res
            };
            if !(proof.token == transfer_data.transfer.token_eth) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(proof.token == transfer_data.transfer.token_eth) {
            ::near_sdk::env::panic_str(
                &{
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &["Wrong token transferred ", ", expected "],
                            &[
                                ::core::fmt::ArgumentV1::new_debug(&proof.token),
                                ::core::fmt::ArgumentV1::new_debug(
                                    &transfer_data.transfer.token_eth,
                                ),
                            ],
                        ),
                    );
                    res
                },
            )
        }
        if true {
            let msg: &str = &{
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &["Wrong amount transferred ", ", expected "],
                        &[
                            ::core::fmt::ArgumentV1::new_display(&proof.amount),
                            ::core::fmt::ArgumentV1::new_display(
                                &transfer_data.transfer.amount.0,
                            ),
                        ],
                    ),
                );
                res
            };
            if !(proof.amount == transfer_data.transfer.amount.0) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(proof.amount == transfer_data.transfer.amount.0) {
            ::near_sdk::env::panic_str(
                &{
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &["Wrong amount transferred ", ", expected "],
                            &[
                                ::core::fmt::ArgumentV1::new_display(&proof.amount),
                                ::core::fmt::ArgumentV1::new_display(
                                    &transfer_data.transfer.amount.0,
                                ),
                            ],
                        ),
                    );
                    res
                },
            )
        }
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
    pub fn get_user_balance(
        &self,
        account_id: &AccountId,
        token_id: &AccountId,
    ) -> u128 {
        let user_balance = self
            .user_balances
            .get(account_id)
            .unwrap_or_else(|| ::core::panicking::panic_display(
                &"User doesn't have balance".to_string(),
            ));
        user_balance
            .get(token_id)
            .unwrap_or_else(|| ::core::panicking::panic_fmt(
                ::core::fmt::Arguments::new_v1(
                    &["User token: ", " , balance is 0"],
                    &[::core::fmt::ArgumentV1::new_display(&token_id)],
                ),
            ))
    }
    fn decrease_balance(
        &mut self,
        user: &AccountId,
        token_id: &AccountId,
        amount: &u128,
    ) {
        let mut user_token_balance = self.user_balances.get(user).unwrap();
        let balance = user_token_balance.get(token_id).unwrap() - amount;
        user_token_balance.insert(token_id, &balance);
        self.user_balances.insert(user, &user_token_balance);
    }
    fn increase_balance(
        &mut self,
        user: &AccountId,
        token_id: &AccountId,
        amount: &u128,
    ) {
        if let Some(mut user_balances) = self.user_balances.get(user) {
            user_balances
                .insert(token_id, &(user_balances.get(token_id).unwrap_or(0) + amount));
        } else {
            let storage_key = [
                StorageKey::UserBalancePrefix.try_to_vec().unwrap().as_slice(),
                user.try_to_vec().unwrap().as_slice(),
            ]
                .concat();
            let mut token_balance = LookupMap::new(storage_key);
            token_balance.insert(token_id, amount);
            self.user_balances.insert(user, &token_balance);
        }
    }
    fn validate_transfer_message(
        &self,
        transfer_message: &TransferMessage,
        sender_id: &AccountId,
    ) {
        if true {
            let msg: &str = &{
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &[
                            "Transfer valid time:",
                            " not correct, current block timestamp:",
                            ".",
                        ],
                        &[
                            ::core::fmt::ArgumentV1::new_display(
                                &transfer_message.valid_till,
                            ),
                            ::core::fmt::ArgumentV1::new_display(&block_timestamp()),
                        ],
                    ),
                );
                res
            };
            if !(transfer_message.valid_till > block_timestamp()) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(transfer_message.valid_till > block_timestamp()) {
            ::near_sdk::env::panic_str(
                &{
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &[
                                "Transfer valid time:",
                                " not correct, current block timestamp:",
                                ".",
                            ],
                            &[
                                ::core::fmt::ArgumentV1::new_display(
                                    &transfer_message.valid_till,
                                ),
                                ::core::fmt::ArgumentV1::new_display(&block_timestamp()),
                            ],
                        ),
                    );
                    res
                },
            )
        }
        let lock_period = transfer_message.valid_till - block_timestamp();
        if true {
            let msg: &str = &{
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &["Lock period:", " does not fit the terms of the contract."],
                        &[::core::fmt::ArgumentV1::new_display(&lock_period)],
                    ),
                );
                res
            };
            if !(self.lock_duration.lock_time_min..=self.lock_duration.lock_time_max)
                .contains(&lock_period)
            {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(self.lock_duration.lock_time_min..=self.lock_duration.lock_time_max)
            .contains(&lock_period)
        {
            ::near_sdk::env::panic_str(
                &{
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &[
                                "Lock period:",
                                " does not fit the terms of the contract.",
                            ],
                            &[::core::fmt::ArgumentV1::new_display(&lock_period)],
                        ),
                    );
                    res
                },
            )
        }
        self.check_whitelist_token_and_account(
            &transfer_message.transfer.token_near,
            sender_id,
        );
        self.check_whitelist_token_and_account(&transfer_message.fee.token, sender_id);
    }
    fn store_transfers(
        &mut self,
        sender_id: AccountId,
        transfer_message: TransferMessage,
    ) -> u128 {
        let new_balance = self
            .pending_transfers_balances
            .get(&transfer_message.transfer.token_near)
            .unwrap_or(0) + transfer_message.transfer.amount.0;
        self.pending_transfers_balances
            .insert(&transfer_message.transfer.token_near, &new_balance);
        self.nonce += 1;
        let transaction_id = utils::get_transaction_id(self.nonce);
        let account_pending = (sender_id, transfer_message);
        self.pending_transfers.insert(&transaction_id, &account_pending);
        self.nonce
    }
    fn remove_transfer(
        &mut self,
        transfer_id: &String,
        transfer_message: &TransferMessage,
    ) {
        let new_balance = self
            .pending_transfers_balances
            .get(&transfer_message.transfer.token_near)
            .unwrap_or_else(|| env::panic_str("Pending balance does not exist"))
            - transfer_message.transfer.amount.0;
        self.pending_transfers_balances
            .insert(&transfer_message.transfer.token_near, &new_balance);
        self.pending_transfers.remove(transfer_id);
    }
    pub fn withdraw(&mut self, token_id: AccountId, amount: U128) {
        let mut __check_paused = true;
        let __except_roles: Vec<&str> = <[_]>::into_vec(
            #[rustc_box]
            ::alloc::boxed::Box::new([Role::UnrestrictedWithdraw.into()]),
        );
        let __except_roles: Vec<String> = __except_roles
            .iter()
            .map(|&x| x.into())
            .collect();
        let may_bypass = self
            .acl_has_any_role(__except_roles, ::near_sdk::env::predecessor_account_id());
        if may_bypass {
            __check_paused = false;
        }
        if __check_paused {
            if true {
                let msg: &str = &"Pausable: Method is paused";
                if !!self.pa_is_paused("withdraw".to_string()) {
                    ::core::panicking::panic_display(&msg)
                }
            } else if !!self.pa_is_paused("withdraw".to_string()) {
                ::near_sdk::env::panic_str(&"Pausable: Method is paused")
            }
        }
        let receiver_id = env::predecessor_account_id();
        let balance = self.get_user_balance(&receiver_id, &token_id);
        if true {
            let msg: &str = &"Not enough token balance";
            if !(balance >= amount.into()) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !(balance >= amount.into()) {
            ::near_sdk::env::panic_str(&"Not enough token balance")
        }
        ext_token::ext(token_id.clone())
            .with_static_gas(utils::tera_gas(5))
            .with_attached_deposit(1)
            .ft_transfer(
                receiver_id.clone(),
                amount,
                Some({
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &["Withdraw from: ", " amount: "],
                            &[
                                ::core::fmt::ArgumentV1::new_display(&current_account_id()),
                                ::core::fmt::ArgumentV1::new_display(
                                    &u128::try_from(amount).unwrap(),
                                ),
                            ],
                        ),
                    );
                    res
                }),
            )
            .then(
                ext_self::ext(current_account_id())
                    .with_static_gas(utils::tera_gas(2))
                    .with_attached_deposit(utils::NO_DEPOSIT)
                    .withdraw_callback(token_id, amount, receiver_id),
            );
    }
    pub fn withdraw_callback(
        &mut self,
        token_id: AccountId,
        amount: U128,
        sender_id: AccountId,
    ) {
        if true {
            let msg: &str = &"Error transfer";
            if !is_promise_success() {
                ::core::panicking::panic_display(&msg)
            }
        } else if !is_promise_success() {
            ::near_sdk::env::panic_str(&"Error transfer")
        }
        self.decrease_balance(&sender_id, &token_id, &u128::try_from(amount).unwrap());
        Event::FastBridgeWithdrawEvent {
            recipient_id: sender_id,
            token: token_id,
            amount,
        }
            .emit();
    }
    pub fn set_prover_account(&mut self, prover_account: AccountId) {
        let __acl_any_roles: Vec<&str> = <[_]>::into_vec(
            #[rustc_box]
            ::alloc::boxed::Box::new([Role::ConfigManager.into()]),
        );
        let __acl_any_roles_ser: Vec<String> = __acl_any_roles
            .iter()
            .map(|&role| role.into())
            .collect();
        let __acl_any_account_id = ::near_sdk::env::predecessor_account_id();
        if !self.acl_has_any_role(__acl_any_roles_ser, __acl_any_account_id) {
            let message = {
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &[
                            "Insufficient permissions for method ",
                            " restricted by access control. Requires one of these roles: ",
                        ],
                        &[
                            ::core::fmt::ArgumentV1::new_display(&"set_prover_account"),
                            ::core::fmt::ArgumentV1::new_debug(&__acl_any_roles),
                        ],
                    ),
                );
                res
            };
            near_sdk::env::panic_str(&message);
        }
        self.prover_account = prover_account;
    }
    pub fn set_enear_address(&mut self, near_address: String) {
        let __acl_any_roles: Vec<&str> = <[_]>::into_vec(
            #[rustc_box]
            ::alloc::boxed::Box::new([Role::ConfigManager.into()]),
        );
        let __acl_any_roles_ser: Vec<String> = __acl_any_roles
            .iter()
            .map(|&role| role.into())
            .collect();
        let __acl_any_account_id = ::near_sdk::env::predecessor_account_id();
        if !self.acl_has_any_role(__acl_any_roles_ser, __acl_any_account_id) {
            let message = {
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &[
                            "Insufficient permissions for method ",
                            " restricted by access control. Requires one of these roles: ",
                        ],
                        &[
                            ::core::fmt::ArgumentV1::new_display(&"set_enear_address"),
                            ::core::fmt::ArgumentV1::new_debug(&__acl_any_roles),
                        ],
                    ),
                );
                res
            };
            near_sdk::env::panic_str(&message);
        }
        if true {
            let msg: &str = &{
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &["Ethereum address:", " not valid."],
                        &[::core::fmt::ArgumentV1::new_display(&near_address)],
                    ),
                );
                res
            };
            if !utils::is_valid_eth_address(near_address.clone()) {
                ::core::panicking::panic_display(&msg)
            }
        } else if !utils::is_valid_eth_address(near_address.clone()) {
            ::near_sdk::env::panic_str(
                &{
                    let res = ::alloc::fmt::format(
                        ::core::fmt::Arguments::new_v1(
                            &["Ethereum address:", " not valid."],
                            &[::core::fmt::ArgumentV1::new_display(&near_address)],
                        ),
                    );
                    res
                },
            )
        }
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
        self.pending_transfers.iter().skip(from_index).take(limit).collect::<Vec<_>>()
    }
    pub fn get_pending_transfer(
        &self,
        id: String,
    ) -> Option<(AccountId, TransferMessage)> {
        self.pending_transfers.get(&id)
    }
    pub fn set_lock_time(&mut self, lock_time_min: String, lock_time_max: String) {
        let __acl_any_roles: Vec<&str> = <[_]>::into_vec(
            #[rustc_box]
            ::alloc::boxed::Box::new([Role::ConfigManager.into()]),
        );
        let __acl_any_roles_ser: Vec<String> = __acl_any_roles
            .iter()
            .map(|&role| role.into())
            .collect();
        let __acl_any_account_id = ::near_sdk::env::predecessor_account_id();
        if !self.acl_has_any_role(__acl_any_roles_ser, __acl_any_account_id) {
            let message = {
                let res = ::alloc::fmt::format(
                    ::core::fmt::Arguments::new_v1(
                        &[
                            "Insufficient permissions for method ",
                            " restricted by access control. Requires one of these roles: ",
                        ],
                        &[
                            ::core::fmt::ArgumentV1::new_display(&"set_lock_time"),
                            ::core::fmt::ArgumentV1::new_debug(&__acl_any_roles),
                        ],
                    ),
                );
                res
            };
            near_sdk::env::panic_str(&message);
        }
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
        self
            .lock_duration = LockDuration {
            lock_time_min,
            lock_time_max,
        };
    }
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn new() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::current_account_id() != near_sdk::env::predecessor_account_id() {
        near_sdk::env::panic_str("Method new is private");
    }
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method new doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        eth_bridge_contract: String,
        prover_account: AccountId,
        eth_client_account: AccountId,
        lock_time_min: String,
        lock_time_max: String,
        eth_block_time: Duration,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __field2,
                    __field3,
                    __field4,
                    __field5,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            2u64 => _serde::__private::Ok(__Field::__field2),
                            3u64 => _serde::__private::Ok(__Field::__field3),
                            4u64 => _serde::__private::Ok(__Field::__field4),
                            5u64 => _serde::__private::Ok(__Field::__field5),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "eth_bridge_contract" => {
                                _serde::__private::Ok(__Field::__field0)
                            }
                            "prover_account" => _serde::__private::Ok(__Field::__field1),
                            "eth_client_account" => {
                                _serde::__private::Ok(__Field::__field2)
                            }
                            "lock_time_min" => _serde::__private::Ok(__Field::__field3),
                            "lock_time_max" => _serde::__private::Ok(__Field::__field4),
                            "eth_block_time" => _serde::__private::Ok(__Field::__field5),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"eth_bridge_contract" => {
                                _serde::__private::Ok(__Field::__field0)
                            }
                            b"prover_account" => _serde::__private::Ok(__Field::__field1),
                            b"eth_client_account" => {
                                _serde::__private::Ok(__Field::__field2)
                            }
                            b"lock_time_min" => _serde::__private::Ok(__Field::__field3),
                            b"lock_time_max" => _serde::__private::Ok(__Field::__field4),
                            b"eth_block_time" => _serde::__private::Ok(__Field::__field5),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 6 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 6 elements",
                                    ),
                                );
                            }
                        };
                        let __field2 = match match _serde::de::SeqAccess::next_element::<
                            AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        2usize,
                                        &"struct Input with 6 elements",
                                    ),
                                );
                            }
                        };
                        let __field3 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        3usize,
                                        &"struct Input with 6 elements",
                                    ),
                                );
                            }
                        };
                        let __field4 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        4usize,
                                        &"struct Input with 6 elements",
                                    ),
                                );
                            }
                        };
                        let __field5 = match match _serde::de::SeqAccess::next_element::<
                            Duration,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        5usize,
                                        &"struct Input with 6 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            eth_bridge_contract: __field0,
                            prover_account: __field1,
                            eth_client_account: __field2,
                            lock_time_min: __field3,
                            lock_time_max: __field4,
                            eth_block_time: __field5,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<AccountId> = _serde::__private::None;
                        let mut __field2: _serde::__private::Option<AccountId> = _serde::__private::None;
                        let mut __field3: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field4: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field5: _serde::__private::Option<Duration> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "eth_bridge_contract",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "prover_account",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field2 => {
                                    if _serde::__private::Option::is_some(&__field2) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "eth_client_account",
                                            ),
                                        );
                                    }
                                    __field2 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field3 => {
                                    if _serde::__private::Option::is_some(&__field3) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "lock_time_min",
                                            ),
                                        );
                                    }
                                    __field3 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field4 => {
                                    if _serde::__private::Option::is_some(&__field4) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "lock_time_max",
                                            ),
                                        );
                                    }
                                    __field4 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field5 => {
                                    if _serde::__private::Option::is_some(&__field5) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "eth_block_time",
                                            ),
                                        );
                                    }
                                    __field5 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            Duration,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field(
                                    "eth_bridge_contract",
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field(
                                    "prover_account",
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field2 = match __field2 {
                            _serde::__private::Some(__field2) => __field2,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field(
                                    "eth_client_account",
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field3 = match __field3 {
                            _serde::__private::Some(__field3) => __field3,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field(
                                    "lock_time_min",
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field4 = match __field4 {
                            _serde::__private::Some(__field4) => __field4,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field(
                                    "lock_time_max",
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field5 = match __field5 {
                            _serde::__private::Some(__field5) => __field5,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field(
                                    "eth_block_time",
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            eth_bridge_contract: __field0,
                            prover_account: __field1,
                            eth_client_account: __field2,
                            lock_time_min: __field3,
                            lock_time_max: __field4,
                            eth_block_time: __field5,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &[
                    "eth_bridge_contract",
                    "prover_account",
                    "eth_client_account",
                    "lock_time_min",
                    "lock_time_max",
                    "eth_block_time",
                ];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input {
        eth_bridge_contract,
        prover_account,
        eth_client_account,
        lock_time_min,
        lock_time_max,
        eth_block_time,
    }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    if near_sdk::env::state_exists() {
        near_sdk::env::panic_str("The contract has already been initialized");
    }
    let contract = FastBridge::new(
        eth_bridge_contract,
        prover_account,
        eth_client_account,
        lock_time_min,
        lock_time_max,
        eth_block_time,
    );
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn init_transfer() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method init_transfer doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        msg: near_sdk::json_types::Base64VecU8,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "msg" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"msg" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            near_sdk::json_types::Base64VecU8,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { msg: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<
                            near_sdk::json_types::Base64VecU8,
                        > = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("msg"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            near_sdk::json_types::Base64VecU8,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("msg") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { msg: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["msg"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { msg }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.init_transfer(msg);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn init_transfer_callback() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::current_account_id() != near_sdk::env::predecessor_account_id() {
        near_sdk::env::panic_str("Method init_transfer_callback is private");
    }
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method init_transfer_callback doesn't accept deposit");
    }
    struct Input {
        transfer_message: TransferMessage,
        sender_id: AccountId,
        update_balance: Option<UpdateBalance>,
    }
    impl borsh::de::BorshDeserialize for Input
    where
        TransferMessage: borsh::BorshDeserialize,
        AccountId: borsh::BorshDeserialize,
        Option<UpdateBalance>: borsh::BorshDeserialize,
    {
        fn deserialize(
            buf: &mut &[u8],
        ) -> ::core::result::Result<Self, borsh::maybestd::io::Error> {
            Ok(Self {
                transfer_message: borsh::BorshDeserialize::deserialize(buf)?,
                sender_id: borsh::BorshDeserialize::deserialize(buf)?,
                update_balance: borsh::BorshDeserialize::deserialize(buf)?,
            })
        }
    }
    let Input { transfer_message, sender_id, update_balance }: Input = near_sdk::borsh::BorshDeserialize::try_from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from Borsh.");
    let data: Vec<u8> = match near_sdk::env::promise_result(0u64) {
        near_sdk::PromiseResult::Successful(x) => x,
        _ => near_sdk::env::panic_str("Callback computation 0 was not successful"),
    };
    let last_block_height: u64 = near_sdk::borsh::BorshDeserialize::try_from_slice(&data)
        .expect("Failed to deserialize callback using Borsh");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract
        .init_transfer_callback(
            last_block_height,
            transfer_message,
            sender_id,
            update_balance,
        );
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn unlock() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        nonce: U128,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "nonce" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"nonce" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            U128,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { nonce: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<U128> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("nonce"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            U128,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("nonce") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { nonce: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["nonce"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { nonce }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.unlock(nonce);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn unlock_callback() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::current_account_id() != near_sdk::env::predecessor_account_id() {
        near_sdk::env::panic_str("Method unlock_callback is private");
    }
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method unlock_callback doesn't accept deposit");
    }
    struct Input {
        nonce: U128,
        sender_id: AccountId,
    }
    impl borsh::de::BorshDeserialize for Input
    where
        U128: borsh::BorshDeserialize,
        AccountId: borsh::BorshDeserialize,
    {
        fn deserialize(
            buf: &mut &[u8],
        ) -> ::core::result::Result<Self, borsh::maybestd::io::Error> {
            Ok(Self {
                nonce: borsh::BorshDeserialize::deserialize(buf)?,
                sender_id: borsh::BorshDeserialize::deserialize(buf)?,
            })
        }
    }
    let Input { nonce, sender_id }: Input = near_sdk::borsh::BorshDeserialize::try_from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from Borsh.");
    let data: Vec<u8> = match near_sdk::env::promise_result(0u64) {
        near_sdk::PromiseResult::Successful(x) => x,
        _ => near_sdk::env::panic_str("Callback computation 0 was not successful"),
    };
    let last_block_height: u64 = near_sdk::borsh::BorshDeserialize::try_from_slice(&data)
        .expect("Failed to deserialize callback using Borsh");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    contract.unlock_callback(last_block_height, nonce, sender_id);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn lp_unlock() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method lp_unlock doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        proof: Proof,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "proof" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"proof" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            Proof,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { proof: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<Proof> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("proof"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            Proof,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("proof") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { proof: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["proof"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { proof }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.lp_unlock(proof);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn verify_log_entry_callback() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::current_account_id() != near_sdk::env::predecessor_account_id() {
        near_sdk::env::panic_str("Method verify_log_entry_callback is private");
    }
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str(
            "Method verify_log_entry_callback doesn't accept deposit",
        );
    }
    struct Input {
        proof: EthTransferEvent,
    }
    impl borsh::de::BorshDeserialize for Input
    where
        EthTransferEvent: borsh::BorshDeserialize,
    {
        fn deserialize(
            buf: &mut &[u8],
        ) -> ::core::result::Result<Self, borsh::maybestd::io::Error> {
            Ok(Self {
                proof: borsh::BorshDeserialize::deserialize(buf)?,
            })
        }
    }
    let Input { proof }: Input = near_sdk::borsh::BorshDeserialize::try_from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from Borsh.");
    let data: Vec<u8> = match near_sdk::env::promise_result(0u64) {
        near_sdk::PromiseResult::Successful(x) => x,
        _ => near_sdk::env::panic_str("Callback computation 0 was not successful"),
    };
    let verification_success: bool = near_sdk::borsh::BorshDeserialize::try_from_slice(
            &data,
        )
        .expect("Failed to deserialize callback using Borsh");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    contract.verify_log_entry_callback(verification_success, proof);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn get_user_balance() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        account_id: AccountId,
        token_id: AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "account_id" => _serde::__private::Ok(__Field::__field0),
                            "token_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"account_id" => _serde::__private::Ok(__Field::__field0),
                            b"token_id" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            account_id: __field0,
                            token_id: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<AccountId> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<AccountId> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "account_id",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "token_id",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("account_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("token_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            account_id: __field0,
                            token_id: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["account_id", "token_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { account_id, token_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.get_user_balance(&account_id, &token_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn withdraw() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        token_id: AccountId,
        amount: U128,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "token_id" => _serde::__private::Ok(__Field::__field0),
                            "amount" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"token_id" => _serde::__private::Ok(__Field::__field0),
                            b"amount" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            U128,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            token_id: __field0,
                            amount: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<AccountId> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<U128> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "token_id",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("amount"),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            U128,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("token_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("amount") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            token_id: __field0,
                            amount: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["token_id", "amount"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { token_id, amount }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    contract.withdraw(token_id, amount);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn withdraw_callback() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::current_account_id() != near_sdk::env::predecessor_account_id() {
        near_sdk::env::panic_str("Method withdraw_callback is private");
    }
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method withdraw_callback doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        token_id: AccountId,
        amount: U128,
        sender_id: AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __field2,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            2u64 => _serde::__private::Ok(__Field::__field2),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "token_id" => _serde::__private::Ok(__Field::__field0),
                            "amount" => _serde::__private::Ok(__Field::__field1),
                            "sender_id" => _serde::__private::Ok(__Field::__field2),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"token_id" => _serde::__private::Ok(__Field::__field0),
                            b"amount" => _serde::__private::Ok(__Field::__field1),
                            b"sender_id" => _serde::__private::Ok(__Field::__field2),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 3 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            U128,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 3 elements",
                                    ),
                                );
                            }
                        };
                        let __field2 = match match _serde::de::SeqAccess::next_element::<
                            AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        2usize,
                                        &"struct Input with 3 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            token_id: __field0,
                            amount: __field1,
                            sender_id: __field2,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<AccountId> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<U128> = _serde::__private::None;
                        let mut __field2: _serde::__private::Option<AccountId> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "token_id",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("amount"),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            U128,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field2 => {
                                    if _serde::__private::Option::is_some(&__field2) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "sender_id",
                                            ),
                                        );
                                    }
                                    __field2 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("token_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("amount") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field2 = match __field2 {
                            _serde::__private::Some(__field2) => __field2,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("sender_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            token_id: __field0,
                            amount: __field1,
                            sender_id: __field2,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &[
                    "token_id",
                    "amount",
                    "sender_id",
                ];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { token_id, amount, sender_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    contract.withdraw_callback(token_id, amount, sender_id);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn set_prover_account() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method set_prover_account doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        prover_account: AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "prover_account" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"prover_account" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { prover_account: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<AccountId> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "prover_account",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field(
                                    "prover_account",
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { prover_account: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["prover_account"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { prover_account }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    contract.set_prover_account(prover_account);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn set_enear_address() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method set_enear_address doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        near_address: String,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "near_address" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"near_address" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { near_address: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "near_address",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("near_address") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { near_address: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["near_address"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { near_address }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    contract.set_enear_address(near_address);
    near_sdk::env::state_write(&contract);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn get_lock_duration() {
    near_sdk::env::setup_panic_hook();
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.get_lock_duration();
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn get_pending_balance() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        token_id: AccountId,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "token_id" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"token_id" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            AccountId,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { token_id: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<AccountId> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "token_id",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            AccountId,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("token_id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { token_id: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["token_id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { token_id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.get_pending_balance(token_id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn get_pending_transfers() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        from_index: usize,
        limit: usize,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "from_index" => _serde::__private::Ok(__Field::__field0),
                            "limit" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"from_index" => _serde::__private::Ok(__Field::__field0),
                            b"limit" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            usize,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            usize,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            from_index: __field0,
                            limit: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<usize> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<usize> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "from_index",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            usize,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("limit"),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            usize,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("from_index") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("limit") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            from_index: __field0,
                            limit: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &["from_index", "limit"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { from_index, limit }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.get_pending_transfers(from_index, limit);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn get_pending_transfer() {
    near_sdk::env::setup_panic_hook();
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        id: String,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "id" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"id" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input { id: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("id"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field("id") {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input { id: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["id"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { id }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    let result = contract.get_pending_transfer(id);
    let result = near_sdk::serde_json::to_vec(&result)
        .expect("Failed to serialize the return value using JSON.");
    near_sdk::env::value_return(&result);
}
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn set_lock_time() {
    near_sdk::env::setup_panic_hook();
    if near_sdk::env::attached_deposit() != 0 {
        near_sdk::env::panic_str("Method set_lock_time doesn't accept deposit");
    }
    #[serde(crate = "near_sdk::serde")]
    struct Input {
        lock_time_min: String,
        lock_time_max: String,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        use near_sdk::serde as _serde;
        #[automatically_derived]
        impl<'de> near_sdk::serde::Deserialize<'de> for Input {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> near_sdk::serde::__private::Result<Self, __D::Error>
            where
                __D: near_sdk::serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __field1,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            1u64 => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "lock_time_min" => _serde::__private::Ok(__Field::__field0),
                            "lock_time_max" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"lock_time_min" => _serde::__private::Ok(__Field::__field0),
                            b"lock_time_max" => _serde::__private::Ok(__Field::__field1),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Input>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Input;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct Input",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        let __field1 = match match _serde::de::SeqAccess::next_element::<
                            String,
                        >(&mut __seq) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        1usize,
                                        &"struct Input with 2 elements",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(Input {
                            lock_time_min: __field0,
                            lock_time_max: __field1,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<String> = _serde::__private::None;
                        let mut __field1: _serde::__private::Option<String> = _serde::__private::None;
                        while let _serde::__private::Some(__key)
                            = match _serde::de::MapAccess::next_key::<
                                __Field,
                            >(&mut __map) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "lock_time_min",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                __Field::__field1 => {
                                    if _serde::__private::Option::is_some(&__field1) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "lock_time_max",
                                            ),
                                        );
                                    }
                                    __field1 = _serde::__private::Some(
                                        match _serde::de::MapAccess::next_value::<
                                            String,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field(
                                    "lock_time_min",
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        let __field1 = match __field1 {
                            _serde::__private::Some(__field1) => __field1,
                            _serde::__private::None => {
                                match _serde::__private::de::missing_field(
                                    "lock_time_max",
                                ) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::__private::Ok(Input {
                            lock_time_min: __field0,
                            lock_time_max: __field1,
                        })
                    }
                }
                const FIELDS: &'static [&'static str] = &[
                    "lock_time_min",
                    "lock_time_max",
                ];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Input",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Input>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    let Input { lock_time_min, lock_time_max }: Input = near_sdk::serde_json::from_slice(
            &near_sdk::env::input().expect("Expected input since method has arguments."),
        )
        .expect("Failed to deserialize input from JSON.");
    let mut contract: FastBridge = near_sdk::env::state_read().unwrap_or_default();
    contract.set_lock_time(lock_time_min, lock_time_max);
    near_sdk::env::state_write(&contract);
}