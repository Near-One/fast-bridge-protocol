use std::convert::TryInto;
use near_sdk::AccountId;

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SpectreBridgeTransferFailedEvent {
    nonce: u128,
    account: AccountId,
}

impl Default for SpectreBridgeTransferFailedEvent {
    fn default() -> Self {
        nonce: 0,
        account: AccountId::from("".to_string()),
    }
}