pub const TGAS: near_sdk::Gas = near_sdk::Gas::ONE_TERA;
pub const NO_DEPOSIT: u128 = 0;

pub fn tera_gas(gas: u64) -> near_sdk::Gas {
    TGAS * gas
}

pub fn get_eth_storage_key_hash(
    token: fast_bridge_common::EthAddress,
    recipient: fast_bridge_common::EthAddress,
    nonce: eth_types::U256,
    amount: eth_types::U256,
) -> Vec<u8> {
    let slot = eth_types::U256(302u128.into());
    let mut be_slot = [0u8; 32];
    slot.0.to_big_endian(&mut be_slot);

    let encoded_slot_key = [
        get_transfer_id(token, recipient, nonce, amount).as_slice(),
        be_slot.as_slice(),
    ]
    .concat();

    near_sdk::env::keccak256(&near_sdk::env::keccak256(&encoded_slot_key))
}

pub fn get_transfer_id(
    token: fast_bridge_common::EthAddress,
    recipient: fast_bridge_common::EthAddress,
    nonce: eth_types::U256,
    amount: eth_types::U256,
) -> Vec<u8> {
    let mut be_nonce = [0u8; 32];
    nonce.0.to_big_endian(&mut be_nonce);
    let mut be_amount = [0u8; 32];
    amount.0.to_big_endian(&mut be_amount);

    let encoded = [
        token.as_slice(),
        recipient.as_slice(),
        be_nonce.as_slice(),
        be_amount.as_slice(),
    ]
    .concat();

    near_sdk::env::keccak256(encoded.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fast_bridge_common::get_eth_address;

    #[test]
    fn test_get_storage_key() {
        let key = get_eth_storage_key_hash(
            get_eth_address("07865c6E87B9F70255377e024ace6630C1Eaa37F".to_owned()),
            get_eth_address("e6220257D157Ec7b481290fD10d2037Cf0E83Ea5".to_owned()),
            eth_types::U256(360u128.into()),
            eth_types::U256(9998u128.into()),
        );
        assert_eq!(
            hex::encode(key),
            "1c8ba9af7041ec3098c4d818db9972f67827520c1db7d022f6c3041b6f40ecc3"
        );

        let key = get_eth_storage_key_hash(
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

    #[test]
    fn test_get_transfer_id() {
        let transfer_id = get_transfer_id(
            get_eth_address("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_owned()),
            get_eth_address("3Cb1d11dAE619d489C12bD30e229Ae13bb707409".to_owned()),
            eth_types::U256(18u128.into()),
            eth_types::U256(99970000000u128.into()),
        );

        assert_eq!(
            hex::encode(transfer_id),
            "5865162292a1e621e20721cf8d0b21295686c82b834bc3139be8240849be8efc"
        );

        let transfer_id = get_transfer_id(
            get_eth_address("AaAAAA20D9E0e2461697782ef11675f668207961".to_owned()),
            get_eth_address("b003DB6E49C55c2fD4Bca506ddDB408039D190c8".to_owned()),
            eth_types::U256(7.into()),
            eth_types::U256(987400000000000000u128.into()),
        );

        assert_eq!(
            hex::encode(transfer_id),
            "8a0b8e93348a672f7eb47b661e2c8ff199344117ab6ea4183c2af5af753a651b"
        );
    }
}
