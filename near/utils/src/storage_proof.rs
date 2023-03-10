use hex::FromHex;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

const STORAGE_KEY_SLOT: u32 = 302;

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct Hex(pub Vec<u8>);

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut s = <String as Deserialize>::deserialize(deserializer)?;
        if s.starts_with("0x") {
            s = s[2..].to_string();
        }
        let result = Vec::from_hex(&s).map_err(|err| serde::de::Error::custom(err.to_string()))?;
        Ok(Hex(result))
    }
}

impl Serialize for Hex {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

#[derive(Serialize, Deserialize)]
pub struct JsonProof {
    pub contract_address: String,
    pub storage_key: Hex,
    pub block_number: String,
    pub header_data: Hex,
    pub account_proof: Vec<Hex>,
    pub expected_account_state: Hex,
    pub storage_key_hash: Hex,
    pub storage_proof: Vec<Hex>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct UnlockProof {
    pub header_data: Hex,
    pub account_proof: Vec<Hex>,
    pub account_data: Hex,
    pub storage_proof: Vec<Hex>,
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

pub fn get_eth_storage_key(
    token: fast_bridge_common::EthAddress,
    recipient: fast_bridge_common::EthAddress,
    nonce: eth_types::U256,
    amount: eth_types::U256,
) -> [u8; 32] {
    let slot = eth_types::U256(STORAGE_KEY_SLOT.into());
    let mut be_slot = [0u8; 32];
    slot.0.to_big_endian(&mut be_slot);

    let encoded_slot_key = [
        get_transfer_id(token, recipient, nonce, amount).as_slice(),
        be_slot.as_slice(),
    ]
    .concat();

    keccak256(&encoded_slot_key)
}
