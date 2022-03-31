use near_sdk::{env, log, require, serde_json};
use near_sdk_sim::types::AccountId;
use near_sdk::serde::{Deserialize, Serialize};
use crate::event::nonce_event::SpectreBridgeNonceEvent;
use crate::event::transfer_event::SpectreBridgeTransferEvent;
use crate::event::transfer_failed_event::SpectreBridgeTransferFailedEvent;
use crate::event::unlock_event::SpectreBridgeUnlockEvent;

mod nonce_event;
mod transfer_event;
mod transfer_failed_event;
mod unlock_event;

const STANDARD: &str = "nep297";
const VERSION: &str = "1.0.0";

enum Events {
    SpectreBridgeNonceEvent,
    SpectreBridgeTransferEvent,
    SpectreBridgeTransferFailedEvent,
    SpectreBridgeUnlockEvent,
}

pub struct Event {
    nonce: SpectreBridgeNonceEvent,
    transfer: SpectreBridgeTransferEvent,
    transfer_failed: SpectreBridgeTransferFailedEvent,
    unlock: SpectreBridgeUnlockEvent
}

impl Default for Event {
    fn default() -> Self {
        Self {
            nonce: SpectreBridgeNonceEvent::default(),
            transfer: SpectreBridgeTransferEvent::default(),
            transfer_failed: SpectreBridgeTransferFailedEvent::default(),
            unlock: SpectreBridgeUnlockEvent::default()
        }
    }
}


impl Event {
    pub fn emit(&mut self, event: Event) {
        let mut data;
        match event {
            Event::SpectreBridgeTransferEvent => { data = serde_json::to_string(self.transfer.into()) }
            Event::SpectreBridgeUnlockEvent=>{data = serde_json::to_string(self.unlock.into())},
            Event::SpectreBridgeTransferFailedEvent=>{data = serde_json::to_string(self.transfer_failed.into())},
            Event::SpectreBridgeNonceEvent=>{data = serde_json::to_string(self.nonce.into())},
        }
        log!(
             r#"EVENT_JSON:{"standard": "{}", "version": "{}", "events": "{}", "data": {}}"#,
            STANDARD,
            VERSION,
            event,
            data.unwrap()
        );
    }
}


