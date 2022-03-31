use crate::{TransferDataEthereum, TransferDataNear};
use crate::types::Address;

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
        nonce: 0,
        valid_till: 0,
        transfer: TransferDataEthereum::default(),
        fee: TransferDataNear::default(),
        recipient: Address::new(),
    }
}