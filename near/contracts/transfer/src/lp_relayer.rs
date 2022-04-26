use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use serde::{Serialize, Deserialize};
use near_sdk::{ext_contract, near_bindgen};
use ethabi::{Event, ParamType, EventParam, Hash, Log, RawLog, Token};
use hex::ToHex;
use eth_types::*;
use crate::utils::{EthAddress, EthEventParams, long_signature};

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

pub struct EthEvent {
    pub locker_address: EthAddress,
    pub log: Log,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct Relayer {
    pub e_near_address: EthAddress,
    pub sender: String,
    pub nonce: u128,
}

impl Default for Relayer {
    fn default() -> Self {
        Self {
            e_near_address: [0u8; 20],
            sender: "".to_string(),
            nonce: 0,
        }
    }
}

impl Relayer {
    pub fn event_params() -> EthEventParams {
        vec![
            ("sender".to_string(), ParamType::String, true),
            ("nonce".to_string(), ParamType::Uint(256), false),
        ]
    }

    pub fn get_param( proof: Proof) -> Self {
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

        let log = event.parse_log(raw_log).expect("Failed to parse event log");
        let event = EthEvent {
            locker_address,
            log,
        };

        let sender = event.log.params[0].value.clone().to_address().unwrap().0;
        let sender = (&sender).encode_hex::<String>();
        let nonce = event.log.params[1]
            .value
            .clone()
            .to_uint()
            .unwrap()
            .as_u128();
        Self {
            e_near_address: event.locker_address,
            sender,
            nonce,
        }
    }

    #[allow(dead_code)]
    pub fn to_log_entry_data(&self) -> Vec<u8> {
        let _name = EVENT_NAME;
        let params = Relayer::event_params();
        let locker_address = self.e_near_address;
        let indexes =  vec![hex::decode(self.sender.clone()).unwrap()];
        let values =vec![Token::Uint(self.nonce.into())];

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

    fn create_proof(sender: String, nonce: u128) -> Proof {
        let event_data = Relayer {
            e_near_address: [0u8; 20],
            sender,
            nonce
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

        let proof: Proof = create_proof(sender.clone(), nonce);

        let param = Relayer::get_param(proof);
        assert_eq!(sender, param.sender);
        assert_eq!(nonce, param.nonce);
    }
}
