use uint::rustc_hex::{ToHex};
use near_sdk::env::sha256;
use near_sdk::Gas;
use ethabi::ParamType;

pub const TGAS: Gas = near_sdk::Gas::ONE_TERA;
pub const NO_DEPOSIT: u128 = 0;

pub type EthAddress = [u8; 20];
pub type EthEventParams = Vec<(String, ParamType, bool)>;

#[allow(dead_code)]
pub fn terra_gas(gas: u64) -> Gas {
    TGAS * gas
}

#[allow(dead_code)]
pub fn get_transaction_id(id: u128) -> String {
    let _id = id.to_string();
    let buffer = _id.as_bytes();
    sha256(buffer)
        .into_iter()
        .take(20)
        .collect::<Vec<_>>()
        .to_hex()
}

#[allow(dead_code)]
pub fn is_valid_eth_address(address: String) -> bool {
    if hex::decode(address.clone()).is_err() {
        return false;
    }

    hex::decode(address).unwrap().len() == 20
}

#[allow(dead_code)]
pub fn get_eth_address(address: String) -> EthAddress {
    let data = hex::decode(address).expect("address should be a valid hex string.");
    assert_eq!(data.len(), 20, "address should be 20 bytes long");
    let mut result = [0u8; 20];
    result.copy_from_slice(&data);
    result
}