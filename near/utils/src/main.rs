use clap::{Parser, Subcommand};
use eth_types::U256;
use fast_bridge_common::TransferMessage;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use storage_proof::{get_eth_storage_key, JsonProof, UnlockProof};

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
        proof: String,
    },
    DecodeUnlockProof {
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
                .expect("Invalid borsh format of the `TransferMessage`");

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
        SubCommand::EncodeUnlockProof { proof } => {
            let json_proof: JsonProof =
                serde_json::from_str(&proof).expect("Invalid json format of the `JsonProof`");
            let unlock_proof = UnlockProof {
                header_data: json_proof.header_data,
                account_proof: json_proof.account_proof,
                account_data: json_proof.expected_account_state,
                storage_proof: json_proof.storage_proof,
            };

            let encoded_unlock_proof = near_sdk::base64::encode(unlock_proof.try_to_vec().unwrap());

            println!(
                "Encoded unlock proof:\n{}",
                serde_json::to_string(&encoded_unlock_proof).unwrap()
            );
        }
        SubCommand::DecodeUnlockProof { proof } => {
            let decoded_base64 = near_sdk::base64::decode(proof).expect("Invalid base64 proof");
            let transfer_message = UnlockProof::try_from_slice(&decoded_base64)
                .expect("Invalid borsh format of the `UnlockProof`");

            println!(
                "Decoded proof:\n{}",
                serde_json::to_string(&transfer_message).unwrap()
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
    use super::*;
    use near_sdk::AccountId;

    #[test]
    fn encode_borsh_account_id() {
        let account_id: AccountId = "client-eth2.goerli.testnet".parse().unwrap();
        let account_id_base64 = near_sdk::base64::encode(account_id.try_to_vec().unwrap());
        println!("Borsh account id: {}", account_id_base64);
    }

    #[test]
    fn encode_storage_key() {
        let storage_key = get_eth_storage_key(
            fast_bridge_common::get_eth_address(
                "BA62BCfcAaFc6622853cca2BE6Ac7d845BC0f2Dc".to_owned(),
            ),
            fast_bridge_common::get_eth_address(
                "574D7e57fE9477fFA470796eE05D85f6aF240C25".to_owned(),
            ),
            U256(368.into()),
            U256(899800000000000000u128.into()),
        );

        println!("block_height:\n{}", 8570800);
        println!("storage_key:\n{}", hex::encode(storage_key));
    }
}
