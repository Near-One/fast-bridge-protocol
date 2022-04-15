use uint::rustc_hex::{ToHex};
use near_sdk::env::sha256;
use near_sdk::Gas;

pub const TGAS: Gas = near_sdk::Gas::ONE_TERA;

pub fn terra_gas(gas: u64) -> Gas {
    TGAS * gas
}

pub fn get_transaction_id(id: u128) -> String {
    let _id = id.to_string();
    let buffer = _id.as_bytes();
    sha256(buffer)
        .into_iter()
        .take(20)
        .collect::<Vec<_>>()
        .to_hex()
}