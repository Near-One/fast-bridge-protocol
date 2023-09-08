use eth_types::{LogEntry, H256};
use ethabi::{Event, EventParam, Hash, ParamType, RawLog};
use fast_bridge_common::*;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;

type EthEventParams = Vec<(String, ParamType, bool)>;

const EVENT_NAME: &str = "TransferTokens";

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct EthTransferEvent {
    pub eth_bridge_contract: EthAddress,
    pub nonce: u128,
    pub relayer: EthAddress,
    pub token: EthAddress,
    pub recipient: EthAddress,
    pub amount: u128,
    pub unlock_recipient: String,
    pub transfer_id: H256,
}

impl EthTransferEvent {
    pub fn event_params() -> EthEventParams {
        vec![
            ("nonce".to_string(), ParamType::Uint(256), true),
            ("relayer".to_string(), ParamType::Address, false),
            ("token".to_string(), ParamType::Address, false),
            ("recipient".to_string(), ParamType::Address, false),
            ("amount".to_string(), ParamType::Uint(256), false),
            ("unlock_recipient".to_string(), ParamType::String, false),
            ("transfer_id".to_string(), ParamType::FixedBytes(32), true),
        ]
    }

    pub fn parse(proof: Proof) -> Self {
        let data = proof.log_entry_data;
        let params = EthTransferEvent::event_params();
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
        let nonce = log.params[0].value.clone().to_uint().unwrap().as_u128();

        let relayer = log.params[1].value.clone().to_address().unwrap().0;
        let token = log.params[2].value.clone().to_address().unwrap().0;
        let recipient = log.params[3].value.clone().to_address().unwrap().0;
        let amount = log.params[4].value.clone().to_uint().unwrap().as_u128();
        let unlock_recipient = log.params[5].value.clone().to_string().unwrap();
        let transfer_id: H256 = log.params[6]
            .value
            .clone()
            .to_fixed_bytes()
            .unwrap()
            .try_into()
            .unwrap();

        Self {
            eth_bridge_contract: EthAddress(locker_address),
            nonce,
            relayer: EthAddress(relayer),
            token: EthAddress(token),
            recipient: EthAddress(recipient),
            amount,
            unlock_recipient,
            transfer_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethabi::{Log, Token};
    use near_sdk::env::keccak256;
    use std::convert::From;

    pub struct EthEvent {
        pub eth_contract_address: EthAddress,
        pub log: Log,
    }

    impl EthEvent {
        pub fn to_log_entry_data(
            name: &str,
            params: EthEventParams,
            locker_address: EthAddress,
            indexes: Vec<Vec<u8>>,
            values: Vec<ethabi::Token>,
        ) -> Vec<u8> {
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
            let params: Vec<ParamType> = event.inputs.iter().map(|p| p.kind.clone()).collect();
            let topics = indexes.into_iter().map(H256::from).collect();
            let log_entry = LogEntry {
                address: locker_address.0.into(),
                topics: vec![vec![long_signature(&event.name, &params).0.into()], topics].concat(),
                data: ethabi::encode(&values),
            };
            rlp::encode(&log_entry).to_vec()
        }
    }

    fn long_signature(name: &str, params: &[ParamType]) -> Hash {
        let mut result = [0u8; 32];
        fill_signature(name, params, &mut result);
        result.into()
    }

    fn fill_signature(name: &str, params: &[ParamType], result: &mut [u8]) {
        let types = params
            .iter()
            .map(ethabi::param_type::Writer::write)
            .collect::<Vec<String>>()
            .join(",");

        let data: Vec<u8> = From::from(format!("{}({})", name, types).as_str());

        let mut sponge = tiny_keccak::Keccak::new_keccak256();
        sponge.update(&data);
        sponge.finalize(result);
    }

    fn to_log_entry_data(event: &EthTransferEvent) -> Vec<u8> {
        EthEvent::to_log_entry_data(
            EVENT_NAME,
            EthTransferEvent::event_params(),
            event.eth_bridge_contract,
            vec![
                event.nonce.to_be_bytes().to_vec(),
                event.transfer_id.0 .0.to_vec(),
            ],
            vec![
                Token::Address(event.relayer.0.into()),
                Token::Address(event.token.0.into()),
                Token::Address(event.recipient.0.into()),
                Token::Uint(event.amount.into()),
                Token::String(event.unlock_recipient.clone()),
            ],
        )
    }

    fn create_proof(transfer_event: &EthTransferEvent) -> Proof {
        Proof {
            log_index: 0,
            log_entry_data: to_log_entry_data(transfer_event),
            receipt_index: 0,
            receipt_data: vec![],
            header_data: vec![],
            proof: vec![],
        }
    }

    #[test]
    fn test_event_data() {
        let eth_bridge_contract =
            get_eth_address("0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
        let nonce: u128 = 200;
        let relayer = get_eth_address("1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
        let token = get_eth_address("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
        let recipient = get_eth_address("3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
        let amount: u128 = 161;
        let transfer_id = [
            token.0.to_vec(),
            recipient.0.to_vec(),
            nonce.to_be_bytes().to_vec(),
            amount.to_be_bytes().to_vec(),
        ]
        .concat();
        let transfer_event = EthTransferEvent {
            eth_bridge_contract,
            token,
            recipient,
            nonce,
            amount,
            transfer_id: keccak256(transfer_id.as_slice()).try_into().unwrap(),
            relayer,
            unlock_recipient: "unlocker.near".to_string(),
        };

        let proof: Proof = create_proof(&transfer_event);
        let param = EthTransferEvent::parse(proof);

        assert_eq!(nonce, param.nonce);
        assert_eq!(relayer, param.relayer);
        assert_eq!(token, param.token);
        assert_eq!(recipient, param.recipient);
        assert_eq!(amount, param.amount);
    }
}
