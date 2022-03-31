use near_sdk::AccountId;
use crate::{TransferDataEthereum, TransferDataNear};

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
        nonce: 0,
        account: AccountId,
        transfer: TransferDataEthereum::default(),
        fee: TransferDataNear::default(),
    }
}