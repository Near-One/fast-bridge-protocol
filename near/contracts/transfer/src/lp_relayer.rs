use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use serde::{Serialize, Deserialize};
use near_sdk::{ext_contract, near_bindgen};
use ethabi::{Event, ParamType, EventParam, Hash, RawLog, Token};
use hex::ToHex;
use eth_types::*;
use crate::utils::{EthEventParams, long_signature};
use spectre_bridge_common::*;

const EVENT_NAME: &str = "TransferToNearInitiated";

#[ext_contract(ext_prover)]
pub trait Prover {
    #[result_serializer(borsh)]
    fn verify_log_entry(
        &self,
        #[serializer(borsh)] log_index: u64,
        #[serializer(borsh)] log_entry_data: Vec<u8>,
        #[serializer(borsh)] receipt_index: u64,
        #[serializer(borsh)] receipt_data: Vec<u8>,
        #[serializer(borsh)] header_data: Vec<u8>,
        #[serializer(borsh)] proof: Vec<Vec<u8>>,
        #[serializer(borsh)] skip_bridge_call: bool,
    ) -> bool;
}


#[derive(Default, BorshDeserialize, BorshSerialize, Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub log_index: u64,
    pub log_entry_data: Vec<u8>,
    pub receipt_index: u64,
    pub receipt_data: Vec<u8>,
    pub header_data: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct Relayer {
    pub e_near_address: EthAddress,
    pub sender: String,
    pub nonce: u128,
    pub chain_id: u32,
}

impl Default for Relayer {
    fn default() -> Self {
        Self {
            e_near_address: [0u8; 20],
            sender: "".to_string(),
            nonce: 0,
            chain_id: 0,
        }
    }
}

impl Relayer {
    pub fn event_params() -> EthEventParams {
        vec![
            ("sender".to_string(), ParamType::Address, true),
            ("nonce".to_string(), ParamType::Uint(256), false),
            ("chain_id".to_string(), ParamType::Uint(32), false),
        ]
    }

    pub fn get_param(e_near_address: EthAddress, proof: spectre_bridge_common::Proof) -> Self {
        let data = proof.log_entry_data;
        let params = Relayer::event_params();
        let event = Event {
            name: EVENT_NAME.to_string(),
            inputs: params
                .into_iter()
                .map(|(name, kind, indexed)| EventParam {
                    name,
                    kind,
                    indexed,
                })
                .collect(),
            anonymous: false,
        };

        let log_entry: LogEntry = rlp::decode(&data).expect("Invalid RLP");
        let locker_address = (log_entry.address.0).0;
        let topics = log_entry
            .topics
            .iter()
            .map(|h| Hash::from(&((h.0).0)))
            .collect();
        let raw_log = RawLog {
            topics,
            data: log_entry.data,
        };

        assert_eq!(
            locker_address,
            e_near_address,
            "Event's address {} does not match locker address of this token {}",
            hex::encode(&locker_address),
            hex::encode(&e_near_address),
        );

        let log = event.parse_log(raw_log).expect("Failed to parse event log");
        let sender = log.params[0].value.clone().to_address().unwrap().0;
        let sender = (&sender).encode_hex::<String>();
        let nonce = log.params[1]
            .value
            .clone()
            .to_uint()
            .unwrap()
            .as_u128();
        let chain_id = log.params[2]
            .value
            .clone()
            .to_uint()
            .unwrap()
            .as_u32();

        Self {
            e_near_address: locker_address,
            sender,
            nonce,
            chain_id,
        }
    }

    #[allow(dead_code)]
    pub fn to_log_entry_data(&self) -> Vec<u8> {
        let _name = EVENT_NAME;
        let params = Relayer::event_params();
        let locker_address = self.e_near_address;
        let indexes = vec![hex::decode(self.sender.clone()).unwrap()];
        let values = vec![Token::Uint(self.nonce.into()), Token::Uint(self.chain_id.into())];

        let event = Event {
            name: EVENT_NAME.to_string(),
            inputs: params
                .into_iter()
                .map(|(name, kind, indexed)| EventParam {
                    name,
                    kind,
                    indexed,
                })
                .collect(),
            anonymous: false,
        };
        let params: Vec<ParamType> = event.inputs.iter().map(|p| p.kind.clone()).collect();
        let topics = indexes.into_iter().map(H256::from).collect();
        let log_entry = LogEntry {
            address: locker_address.into(),
            topics: vec![vec![long_signature(&event.name, &params).0.into()], topics].concat(),
            data: ethabi::encode(&values),
        };
        rlp::encode(&log_entry)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils;
    use super::*;

    fn e_near_eth_address() -> String {
        "68a3637ba6e75c0f66b61a42639c4e9fcd3d4824".to_string()
    }

    fn fake_e_near_eth_address() -> String {
        "34567890F73hdyr6378rrjgoid73hhg73hfh37jfu".to_string()
    }

    fn create_proof(sender: String, nonce: u128, chain_id: u32) -> Proof {
        let event_data = Relayer {
            e_near_address: utils::get_eth_address(e_near_eth_address()),
            sender,
            nonce,
            chain_id,
        };

        Proof {
            log_index: 0,
            log_entry_data: event_data.to_log_entry_data(),
            receipt_index: 0,
            receipt_data: vec![],
            header_data: vec![],
            proof: vec![],
        }
    }


    #[test]
    fn test_event_data() {
        let sender: String = "00005474e89094c44da98b954eedeac495271d0f".to_string();
        let nonce = 1023441230023;
        let chain_id = 5;

        let proof: Proof = create_proof(sender.clone(), nonce, chain_id);

        let param = Relayer::get_param(utils::get_eth_address(e_near_eth_address()), proof);
        assert_eq!(sender, param.sender);
        assert_eq!(nonce, param.nonce);
        assert_eq!(chain_id, param.chain_id);
    }

    #[test]
    #[should_panic]
    fn test_event_data_fail() {
        let sender: String = "00005474e89094c44da98b954eedeac495271d0f".to_string();
        let nonce = 1023441230023;
        let chain_id = 5;

        let proof: Proof = create_proof(sender.clone(), nonce, chain_id);

        let param = Relayer::get_param(utils::get_eth_address(fake_e_near_eth_address()), proof);
        assert_eq!(sender, param.sender);
        assert_eq!(nonce, param.nonce);
        assert_eq!(chain_id, param.chain_id);
    }
}
