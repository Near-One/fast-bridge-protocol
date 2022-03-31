use std::str::FromStr;
use near_sdk::AccountId;
use crate::types::Address;

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TransferDataEthereum {
    token: Address,
    amount: u128,
}

impl Default for TransferDataEthereum {
    fn default() -> Self {
        TransferDataEthereum {
            token: 0,
            amount: 0,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TransferDataNear {
    token: AccountId,
    amount: u128,
}

impl Default for TransferDataNear {
    fn default() -> Self {
        TransferDataNear {
            token: AccountId::from_str("").unwrap(),
            amount: 0,
        }
    }
}