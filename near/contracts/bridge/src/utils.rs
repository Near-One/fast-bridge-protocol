pub const TGAS: near_sdk::Gas = near_sdk::Gas::ONE_TERA;
pub const NO_DEPOSIT: u128 = 0;

pub fn tera_gas(gas: u64) -> near_sdk::Gas {
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

#[allow(dead_code)]
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
        )
    }

    #[test]
    fn test_get_transfer_id_2() {
        let transfer_id = get_transfer_id(
            get_eth_address("AaAAAA20D9E0e2461697782ef11675f668207961".to_owned()),
            get_eth_address("b003DB6E49C55c2fD4Bca506ddDB408039D190c8".to_owned()),
            eth_types::U256(7.into()),
            eth_types::U256(987400000000000000u128.into()),
        );

        assert_eq!(
            hex::encode(transfer_id),
            "8a0b8e93348a672f7eb47b661e2c8ff199344117ab6ea4183c2af5af753a651b"
        )
    }
}
