use near_sdk::Gas;

pub const TGAS: Gas = near_sdk::Gas::ONE_TERA;
pub const NO_DEPOSIT: u128 = 0;

pub fn terra_gas(gas: u64) -> Gas {
    TGAS * gas
}

pub fn get_transaction_id(id: u128) -> String {
    id.to_string()
}

pub fn is_valid_eth_address(address: String) -> bool {
    if hex::decode(address.clone()).is_err() {
        return false;
    }

    hex::decode(address).unwrap().len() == 20
}

pub fn get_eth_address(address: String) -> spectre_bridge_common::EthAddress {
    let data = hex::decode(address).expect("address should be a valid hex string.");
    assert_eq!(data.len(), 20, "address should be 20 bytes long");
    let mut result = [0u8; 20];
    result.copy_from_slice(&data);
    result
}
