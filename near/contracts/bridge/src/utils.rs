pub const TGAS: near_sdk::Gas = near_sdk::Gas::ONE_TERA;
pub const NO_DEPOSIT: u128 = 0;

pub fn tera_gas(gas: u64) -> near_sdk::Gas {
    TGAS * gas
}

pub fn get_transaction_id(id: u128) -> String {
    id.to_string()
}

pub fn get_storage_key(
    token: fast_bridge_common::EthAddress,
    recipient: fast_bridge_common::EthAddress,
    nonce: eth_types::U256,
    amount: eth_types::U256,
) -> Vec<u8> {
    let slot = eth_types::U256(302u128.into());
    let mut be_nonce = [0u8; 32];
    nonce.0.to_big_endian(&mut be_nonce);
    let mut be_amount = [0u8; 32];
    amount.0.to_big_endian(&mut be_amount);
    let mut be_slot = [0u8; 32];
    slot.0.to_big_endian(&mut be_slot);

    let encoded = [
        token.as_slice(),
        recipient.as_slice(),
        be_nonce.as_slice(),
        be_amount.as_slice(),
    ]
    .concat();
    
    let encoded_slot_key = [
        (near_sdk::env::keccak256(&encoded.as_slice())).as_slice(),
        be_slot.as_slice(),
    ].concat();
    
    near_sdk::env::keccak256(&near_sdk::env::keccak256(&encoded_slot_key.as_slice()))
}

pub fn is_valid_eth_address(address: String) -> bool {
    if hex::decode(address.clone()).is_err() {
        return false;
    }

    hex::decode(address).unwrap().len() == 20
}

#[cfg(test)]
mod tests {
    use super::*;
    use fast_bridge_common::get_eth_address;

    #[test]
    fn test_get_transfer() {
        let key = get_storage_key(
            get_eth_address("07865c6E87B9F70255377e024ace6630C1Eaa37F".to_owned()),
            get_eth_address("e6220257D157Ec7b481290fD10d2037Cf0E83Ea5".to_owned()),
            eth_types::U256(360u128.into()),
            eth_types::U256(9998u128.into()),
        );
        assert_eq!(
            hex::encode(key),
            "1c8ba9af7041ec3098c4d818db9972f67827520c1db7d022f6c3041b6f40ecc3"
        )
    }

    #[test]
    fn test_get_transfer_2() {
        let key = get_storage_key(
            get_eth_address("AaAAAA20D9E0e2461697782ef11675f668207961".to_owned()),
            get_eth_address("b003DB6E49C55c2fD4Bca506ddDB408039D190c8".to_owned()),
            eth_types::U256(280u128.into()),
            eth_types::U256(724086u128.into()),
        );
        assert_eq!(
            hex::encode(key),
            "60e979b180901ec1152fddb47e802ab453064c65b53836ae48def371c2648e6d"
        )
    }

}
