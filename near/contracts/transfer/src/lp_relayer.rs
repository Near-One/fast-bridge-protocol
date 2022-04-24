use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use serde::{Serialize, Deserialize};
use near_sdk::{ext_contract, near_bindgen};
use ethabi::{Event, ParamType, EventParam, Hash, Log, RawLog};
use hex::ToHex;
use eth_types::*;
use crate::utils::{EthAddress, EthEventParams};

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
    pub sender: String,
    pub nonce: u128,
}

impl Default for Relayer {
    fn default() -> Self {
        Self {
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
        let name = "TransferToNearInitiated";
        let params = Relayer::event_params();

        let event = Event {
            name: name.to_string(),
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
            sender,
            nonce,
        }
    }
}