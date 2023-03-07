use clap::{Parser, Subcommand};
use eth_types::U256;
use fast_bridge_common::TransferMessage;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use storage_proof::{get_eth_storage_key, JsonProof, UnlockProof};

use crate::storage_proof::UnlockArgs;

mod storage_proof;

#[derive(Subcommand, Debug)]
enum SubCommand {
    EncodeTransferMsg {
        #[clap(short, long)]
        msg: String,
    },
    DecodeTransferMsg {
        #[clap(short, long)]
        msg: String,
    },
    GetTransferStorageKey {
        #[clap(short, long)]
        nonce: u128,
        #[clap(short, long)]
        msg: String,
    },
    EncodeUnlockProof {
        #[clap(short, long)]
        nonce: u128,
        #[clap(short, long)]
        proof: String,
    },
}

#[derive(Parser, Debug)]
#[clap(version)]
struct Arguments {
    #[command(subcommand)]
    cmd: SubCommand,
}

fn main() {
    let args = Arguments::parse();

    match args.cmd {
        SubCommand::EncodeTransferMsg { msg } => {
            let transfer_message: TransferMessage =
                serde_json::from_str(&msg).expect("Invalid json format of the `TransferMessage`");
            let encoded_transfer_message =
                near_sdk::base64::encode(transfer_message.try_to_vec().unwrap());
            println!(
                "Encoded message:\n{}",
                serde_json::to_string(&encoded_transfer_message).unwrap()
            );
        }
        SubCommand::DecodeTransferMsg { msg } => {
            let decoded_base64 = near_sdk::base64::decode(msg).expect("Invalid base64 message");
            let transfer_message = TransferMessage::try_from_slice(&decoded_base64)
                .expect("Invalid json format of the `TransferMessage`");

            println!(
                "Decoded message:\n{}",
                serde_json::to_string(&transfer_message).unwrap()
            );
        }
        SubCommand::GetTransferStorageKey { nonce, msg } => {
            let msg = fix_json_msg_formating(msg);
            let transfer_message: TransferMessage =
                serde_json::from_str(&msg).expect("Invalid json format of the `TransferMessage`");
            let storage_key = get_eth_storage_key(
                transfer_message.transfer.token_eth,
                transfer_message.recipient,
                U256(nonce.into()),
                U256(transfer_message.transfer.amount.0.into()),
            );

            println!(
                "block_height:\n{}",
                transfer_message.valid_till_block_height.unwrap()
            );
            println!("storage_key:\n{}", hex::encode(storage_key));
        }
        SubCommand::EncodeUnlockProof { nonce, proof } => {
            let json_proof: JsonProof =
                serde_json::from_str(&proof).expect("Invalid json format of the `JsonProof`");
            let unlock_proof = UnlockProof {
                header_data: json_proof.header_data.bytes,
                account_proof: json_proof
                    .account_proof
                    .into_iter()
                    .map(|x| x.bytes)
                    .collect(),
                account_data: json_proof.expected_account_state.bytes,
                storage_proof: json_proof
                    .storage_proof
                    .into_iter()
                    .map(|x| x.bytes)
                    .collect(),
            };

            let unlock_args = UnlockArgs {
                nonce: nonce.into(),
                proof: unlock_proof,
            };

            let encoded_unlock_args = near_sdk::base64::encode(unlock_args.try_to_vec().unwrap());

            println!(
                "Encoded unlock args:\n{}",
                serde_json::to_string(&encoded_unlock_args).unwrap()
            );
        }
    }
}

fn fix_json_msg_formating(msg: String) -> String {
    msg.replace("'", "\"")
        .replace("valid_till:", "\"valid_till\":")
        .replace("transfer:", "\"transfer\":")
        .replace("token_near:", "\"token_near\":")
        .replace("token_eth:", "\"token_eth\":")
        .replace("amount:", "\"amount\":")
        .replace("fee:", "\"fee\":")
        .replace("token:", "\"token\":")
        .replace("recipient:", "\"recipient\":")
        .replace("valid_till_block_height:", "\"valid_till_block_height\":")
}

#[cfg(test)]
mod tests {
    use near_sdk::AccountId;
    use super::*;

    #[test]
    fn encode_borsh_account_id() {
        let account_id: AccountId = "client-eth2.goerli.testnet".parse().unwrap();
        let account_id_base64 = near_sdk::base64::encode(account_id.try_to_vec().unwrap());
        println!("Borsh account id: {}", account_id_base64);
    }
}