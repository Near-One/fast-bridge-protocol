use near_sdk::borsh::BorshSerialize;
use near_sdk::{AccountId, env};
use near_sdk_sim::transaction::LogEntry;
use ethabi::{Event, EventParam, Hash, Log, ParamType, RawLog, Token};

pub type EthAddress = [u8; 20];
pub type EthEventParams = Vec<(String, ParamType, bool)>;

#[derive(Debug, Eq, PartialEq)]
pub struct TransferToNearInitiatedEvent {
    pub e_near_address: EthAddress,
    pub sender: String,
    pub nonce: u128,
}

#[derive(Default, BorshDeserialize, BorshSerialize, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub log_index: u64,
    pub log_entry_data: Vec<u8>,
    pub receipt_index: u64,
    pub receipt_data: Vec<u8>,
    pub header_data: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
}

impl Relayer {
    pub fn get_nonce(&mut self, #[serializer(borsh)] proof: Proof) -> u128 {
        self.from_log_entry_data(&proof.log_entry_data).nonce
    }

    pub fn eth_event_from_entry_data(name: &str, params: EthEventParams, data: &[u8]) -> Self {
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
        let log_entry: LogEntry = rlp::decode(data).expect("Invalid RLP");
        let locker_address = (log_entry.address.clone().0).0;
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
        Self {
            locker_address,
            log,
        }
    }

    pub fn from_log_entry_data(&mut self, data: &[u8]) -> Self {
        let event = self.eth_event_from_entry_data(
            "TransferToNearInitiated",
            TransferToNearInitiatedEvent::event_params(),
            data,
        );

        //TODO: change to fields and get nonce
        let sender = event.log.params[0].value.clone().to_address().unwrap().0;
        let sender = (&sender).encode_hex::<String>();
        let nonce = event.log.params[1]
            .value
            .clone()
            .to_uint()
            .unwrap()
            .as_u128();
        TransferToNearInitiatedEvent {
            e_near_address: event.locker_address,
            sender,
            nonce,
        }
    }

    pub fn is_valid_eth_address(address: String) -> bool {
        if hex::decode(address.clone()).is_err() {
            return false;
        }

        hex::decode(address).unwrap().len() == 20
    }

    pub fn get_eth_address(address: String) -> EthAddress {
        let data = hex::decode(address).expect("address should be a valid hex string.");
        assert_eq!(data.len(), 20, "address should be 20 bytes long");
        let mut result = [0u8; 20];
        result.copy_from_slice(&data);
        result
    }
}