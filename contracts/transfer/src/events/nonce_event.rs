use std::str::FromStr;
use near_sdk::AccountId;
use crate::TransferDataEthereum;
use crate::types::Address;

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