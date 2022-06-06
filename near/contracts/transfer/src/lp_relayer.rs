use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use serde::{Serialize, Deserialize};
use near_sdk::{ext_contract, near_bindgen};
use ethabi::{Event, ParamType, EventParam, Hash, RawLog};
use eth_types::*;
use crate::utils::{EthEventParams, long_signature};

const EVENT_NAME: &str = "TransferTokens";

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Default)]
pub struct Relayer {
    pub e_near_address: spectre_bridge_common::EthAddress,
    pub nonce: u128,
    pub relayer: spectre_bridge_common::EthAddress,
    pub token: spectre_bridge_common::EthAddress,
    pub recipient: spectre_bridge_common::EthAddress,
    pub amount: u128,
}

impl Relayer {
    pub fn event_params() -> EthEventParams {
        vec![
            ("nonce".to_string(), ParamType::Uint(256), false)
                ("relayer".to_string(), ParamType::Address, false),
            ("token".to_string(), ParamType::Address, false),
            ("recipient".to_string(), ParamType::Address, false),
            ("amount".to_string(), ParamType::Uint(256), false),
        ]
    }

    pub fn get_param(e_near_address: spectre_bridge_common::EthAddress, proof: spectre_bridge_common::Proof) -> Self {
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
        let log = event.parse_log(raw_log).expect("Failed to parse event log");
        let nonce = log.params[0]
            .value
            .clone()
            .to_uint()
            .unwrap()
            .as_u128();

        let relayer = log.params[1].value.clone().to_address().unwrap().0;
        let relayer = (&relayer).encode_hex::<String>();
        let token = log.params[2].value.clone().to_address().unwrap().0;
        let token = (&token).encode_hex::<String>();
        let recipient = log.params[3].value.clone().to_address().unwrap().0;
        let recipient = (&recipient).encode_hex::<String>();

        let amount = event.log.params[4]
            .value
            .clone()
            .to_uint()
            .unwrap()
            .as_u128();
        Self {
            e_near_address: locker_address,
            nonce,
            relayer,
            token,
            recipient,
            amount,
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
    use crate::utils;
    use super::*;
    use spectre_bridge_common::*;

    fn create_proof(relayer: String, processed_hash: String) -> spectre_bridge_common::Proof {
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
        let relayer = "2a23e0fa3afe77aff5dc6c6a007e3a10c1450633".to_string();
        let processed_hash = "0f98ded191bd93679652d2c8f62c5356b2115d0785954273e90521dbe4c851a9".to_string();
        let proof: Proof = create_proof(relayer, processed_hash);

        let param = Relayer::get_param(proof);
        assert_eq!(sender, param.sender);
        assert_eq!(amount, param.amount);
    }
}
