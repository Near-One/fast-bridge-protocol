use near_sdk::{log, serde_json, AccountId, json_types::U128, serde::Serialize};
use serde_json::json;
use crate::Proof;
use crate::utils::EthAddress;

const STANDARD: &str = "nep297";
const VERSION: &str = "1.0.0";

#[derive(Serialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct TransferDataEthereum {
    token: EthAddress,
    amount: U128,
}

#[derive(Serialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct TransferDataNear {
    pub(crate) token: AccountId,
    pub(crate) amount: U128,
}

#[derive(Serialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
#[serde(tag = "event", content = "data")]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
#[allow(dead_code)]
pub enum Event<'a> {
    SpectreBridgeNonceEvent {
        nonce: &'a U128,
        account: &'a AccountId,
        transfer: &'a TransferDataEthereum,
        recipient: &'a EthAddress,
    },
    SpectreBridgeTransferEvent {
        nonce: &'a U128,
        valid_till: u64,
        transfer: &'a TransferDataNear,
        fee: &'a TransferDataNear,
        recipient: &'a EthAddress,
    },
    SpectreBridgeTransferFailedEvent {
        nonce: &'a U128,
        account: &'a AccountId,
    },
    SpectreBridgeUnlockEvent {
        nonce: &'a U128,
        account: &'a AccountId,
    },
    SpectreBridgeDepositEvent {
        account: &'a AccountId,
        token: &'a AccountId,
        amount: &'a U128,
    },
   SpectreBridgeEthProoverNotProofedEvent{
        nonce: &'a U128,
        proof: &'a Proof
    }
}

impl Event<'_> {
    #[allow(dead_code)]
    pub fn emit(&self) {
        emit_event(&self);
    }
}

#[derive(Serialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct EventMessage {
    standard: String,
    version: String,
    event: serde_json::Value,
    data: [serde_json::Value; 1],
}

#[allow(dead_code)]
pub(crate) fn emit_event<T: ?Sized + Serialize>(data: &T) {
    let result = json!(data);
    let event_json = json!(EventMessage {
        standard: STANDARD.to_string(),
        version: VERSION.to_string(),
        event: result["event"].clone(),
        data: [result["data"].clone()]
    }).to_string();
    log!(format!("EVENT_JSON:{}", event_json));
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::{test_utils, AccountId};
    use crate::utils;

    fn alice() -> AccountId {
        AccountId::new_unchecked("alice".to_string())
    }

    fn get_eth_address() -> EthAddress {
        let address: String = "71C7656EC7ab88b098defB751B7401B5f6d8976F".to_string();
        utils::get_eth_address(address)
    }

    #[test]
    fn nonce_event_test() {
        let nonce = &U128(238);
        let validator_id = &alice();
        let amount = U128(100);
        let token_address = get_eth_address();
        Event::SpectreBridgeNonceEvent {
            nonce,
            account: validator_id,
            transfer: &TransferDataEthereum { token: token_address, amount },
            recipient: &token_address,
        }.emit();
        assert_eq!(
            test_utils::get_logs()[0],
            r#"EVENT_JSON:{"standard":"nep297","version":"1.0.0","event":"spectre_bridge_nonce_event","data":[{"nonce":"238","account":"alice","transfer":{"token":[113,199,101,110,199,171,136,176,152,222,251,117,27,116,1,181,246,216,151,111],"amount":"100"},"recipient":[113,199,101,110,199,171,136,176,152,222,251,117,27,116,1,181,246,216,151,111]}]}"#
        );
    }

    #[test]
    fn failed_event_test() {
        let nonce = &U128(238);
        let validator_id = &alice();
        Event::SpectreBridgeTransferFailedEvent {
            nonce,
            account: validator_id,
        }.emit();
        assert_eq!(
            test_utils::get_logs()[0],
            r#"EVENT_JSON:{"standard":"nep297","version":"1.0.0","event":"spectre_bridge_transfer_failed_event","data":[{"nonce":"238","account":"alice"}]}"#
        );
    }

    #[test]
    fn transfer_event_test() {
        let nonce = &U128(238);
        let validator_id = alice();
        let token_address = get_eth_address();
        let amount: u128 = 100;
        Event::SpectreBridgeTransferEvent {
            nonce,
            valid_till: 0,
            transfer: &TransferDataNear { token: validator_id.clone(), amount: U128(amount) },
            fee: &TransferDataNear { token: validator_id, amount: U128(amount) },
            recipient: &token_address,
        }.emit();
        assert_eq!(
            test_utils::get_logs()[0],
            r#"EVENT_JSON:{"standard":"nep297","version":"1.0.0","event":"spectre_bridge_transfer_event","data":[{"nonce":"238","valid_till":0,"transfer":{"token":"alice","amount":"100"},"fee":{"token":"alice","amount":"100"},"recipient":[113,199,101,110,199,171,136,176,152,222,251,117,27,116,1,181,246,216,151,111]}]}"#
        );
    }

    #[test]
    fn unlock_event_test() {
        let nonce = &U128(238);
        let validator_id = alice();
        Event::SpectreBridgeUnlockEvent {
            nonce,
            account: &validator_id,
        }.emit();
        assert_eq!(
            test_utils::get_logs()[0],
            r#"EVENT_JSON:{"standard":"nep297","version":"1.0.0","event":"spectre_bridge_unlock_event","data":[{"nonce":"238","account":"alice"}]}"#
        );
    }
}
