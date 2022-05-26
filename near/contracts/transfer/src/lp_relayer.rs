use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use serde::{Serialize, Deserialize};
use near_sdk::{ext_contract, near_bindgen};
use ethabi::{Event, ParamType, EventParam, Hash, RawLog};
use eth_types::*;
use crate::utils::{EthAddress, EthEventParams, long_signature};

const EVENT_NAME: &str = "TransferTokens";

#[ext_contract(ext_prover)]
pub trait Prover {
    fn verify_log_entry(
        &self,
        log_index: u64,
        log_entry_data: Vec<u8>,
        receipt_index: u64,
        receipt_data: Vec<u8>,
        header_data: Vec<u8>,
        proof: Vec<Vec<u8>>,
        skip_bridge_call: bool,
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
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Default)]
pub struct Relayer {
    pub e_near_address: EthAddress,
}

impl Relayer {
    pub fn event_params() -> EthEventParams {
        vec![
            ("relayer".to_string(), ParamType::Address, false),
            ("processedHash".to_string(), ParamType::FixedBytes(32), false),
        ]
    }

    pub fn get_param(proof: Proof) -> Self {
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
            data: log_entry.data.clone(),
        };
        let _log = event.parse_log(raw_log).expect("Failed to parse event log");

        Self {
            e_near_address: locker_address,
        }
    }

    #[allow(dead_code)]
    pub fn to_log_entry_data(&self, relayer: String, processed_hash: String) -> Vec<u8> {
        let _name = EVENT_NAME;
        let params = Relayer::event_params();
        let locker_address = self.e_near_address;
        let indexes = vec![hex::decode(relayer.clone()).unwrap(),
                           hex::decode(processed_hash.clone()).unwrap()];
        let values = vec![];

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
    use super::*;

    fn create_proof(relayer: String, processed_hash: String) -> Proof {
        let event_data = Relayer {
            e_near_address: [0u8; 20],
        };

        Proof {
            log_index: 0,
            log_entry_data: event_data.to_log_entry_data(relayer, processed_hash),
            receipt_index: 0,
            receipt_data: vec![],
            header_data: vec![],
            proof: vec![],
        }
    }


    #[test]
    fn test_event_data() {
        let relayer =  "2a23e0fa3afe77aff5dc6c6a007e3a10c1450633".to_string();
        let processed_hash = "0f98ded191bd93679652d2c8f62c5356b2115d0785954273e90521dbe4c851a9".to_string();
        let proof: Proof = create_proof(relayer, processed_hash);

        let param = Relayer::get_param(proof);
        assert_eq!(sender, param.sender);
        assert_eq!(amount, param.amount);
    }
}
