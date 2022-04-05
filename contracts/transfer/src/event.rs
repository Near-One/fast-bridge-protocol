use std::fmt;
use near_sdk::{log, serde_json};
use serde_json::json;
use near_sdk::serde::{Deserialize, Serialize};
use std::str::FromStr;
use crate::AccountId;
use crate::transfer_data::{TransferDataEthereum, TransferDataNear};

const STANDARD: &str = "nep297";
const VERSION: &str = "1.0.0";

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SpectreBridgeNonceEvent {
    nonce: u128,
    account: AccountId,
    transfer: TransferDataEthereum,
    recipient: Address,
}

impl Default for SpectreBridgeNonceEvent {
    fn default() -> Self {
        SpectreBridgeNonceEvent {
            nonce: 0,
            account: AccountId::from_str("").unwrap(),
            transfer: TransferDataEthereum::default(),
            recipient: Address,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SpectreBridgeTransferEvent {
    nonce: u128,
    valid_till: u64,
    transfer: TransferDataEthereum,
    fee: TransferDataNear,
    recipient: Address,
}

impl Default for SpectreBridgeTransferEvent {
    fn default() -> Self {
        SpectreBridgeTransferEvent {
            nonce: 0,
            valid_till: 0,
            transfer: TransferDataEthereum::default(),
            fee: TransferDataNear::default(),
            recipient: Address,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SpectreBridgeTransferFailedEvent {
    nonce: u128,
    account: AccountId,
}

impl Default for SpectreBridgeTransferFailedEvent {
    fn default() -> Self {
        SpectreBridgeTransferFailedEvent {
            nonce: 0,
            account: AccountId::from_str("").unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SpectreBridgeUnlockEvent {
    nonce: u128,
    account: AccountId,
    transfer: TransferDataEthereum,
    fee: TransferDataNear,
}

impl Default for SpectreBridgeUnlockEvent {
    fn default() -> Self {
        SpectreBridgeUnlockEvent {
            nonce: 0,
            account: AccountId::from_str("").unwrap(),
            transfer: TransferDataEthereum::default(),
            fee: TransferDataNear::default(),
        }
    }
}

enum Events {
    SpectreBridgeNonceEvent,
    SpectreBridgeTransferEvent,
    SpectreBridgeTransferFailedEvent,
    SpectreBridgeUnlockEvent,
}

impl fmt::Display for Events {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Events::SpectreBridgeNonceEvent => write!(f, "SpectreBridgeNonceEvent"),
            Events::SpectreBridgeTransferEvent => write!(f, "SpectreBridgeTransferEvent"),
            Events::SpectreBridgeTransferFailedEvent => write!(f, "SpectreBridgeTransferFailedEvent"),
            Events::SpectreBridgeUnlockEvent => write!(f, "SpectreBridgeUnlockEvent"),
        }
    }
}

pub struct Event {
    nonce: SpectreBridgeNonceEvent,
    transfer: SpectreBridgeTransferEvent,
    transfer_failed: SpectreBridgeTransferFailedEvent,
    unlock: SpectreBridgeUnlockEvent,
}

impl Default for Event {
    fn default() -> Self {
        Self {
            nonce: SpectreBridgeNonceEvent::default(),
            transfer: SpectreBridgeTransferEvent::default(),
            transfer_failed: SpectreBridgeTransferFailedEvent::default(),
            unlock: SpectreBridgeUnlockEvent::default(),
        }
    }
}


impl Event {
    pub fn emit(&mut self, event: Events) {
        let mut data;
        match event {
            Events::SpectreBridgeTransferEvent => { data = serde_json::to_string(&self.transfer) }
            Events::SpectreBridgeUnlockEvent => { data = serde_json::to_string(&self.unlock) }
            Events::SpectreBridgeTransferFailedEvent => { data = serde_json::to_string(&self.transfer_failed) }
            Events::SpectreBridgeNonceEvent => { data = serde_json::to_string(&self.nonce) }
        }
        let message = json!({
            "standard": STANDARD,
            "version": VERSION,
            "event": event.to_string(),
            "data": data.unwrap()
        });
        log!(r#"EVENT_JSON:"#.to_owned()+&message.to_string()+"r#");
    }
}


