use fast_bridge_common::TransferMessage;
use near_sdk::{Gas, json_types::U128};
use eth_encode_packed::SolidityDataType;
use eth_types::near_keccak256;

pub const TGAS: Gas = near_sdk::Gas::ONE_TERA;
pub const NO_DEPOSIT: u128 = 0;

pub fn tera_gas(gas: u64) -> Gas {
    TGAS * gas
}

pub fn get_transaction_id(id: u128) -> String {
    id.to_string()
}

pub fn get_processed_hash(transfer_data: TransferMessage, nonce: U128) -> [u8; 32] {
    let args = vec![
        SolidityDataType::Address(transfer_data.transfer.token_eth.into()),
        SolidityDataType::Address(transfer_data.recipient.into()),
        SolidityDataType::Number(u128::try_from(nonce).unwrap().into()),
        SolidityDataType::Number(u128::try_from(transfer_data.transfer.amount).unwrap().into())
    ];

    let (encoded_data, _) = eth_encode_packed::abi::encode_packed(&args);
    near_keccak256(&encoded_data)
}

pub fn is_valid_eth_address(address: String) -> bool {
    if eth_encode_packed::hex::decode(address.clone()).is_err() {
        return false;
    }

    eth_encode_packed::hex::decode(address).unwrap().len() == 20
}
