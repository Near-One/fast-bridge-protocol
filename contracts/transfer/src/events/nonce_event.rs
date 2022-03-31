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
            account: AccountId::from("".to_string()),
            transfer: TransferDataEthereum::default(),
            recipient: Address,
        }
    }
}