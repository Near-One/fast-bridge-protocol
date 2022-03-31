use std::convert::TryInto;
use std::str::FromStr;
use near_sdk::AccountId;

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