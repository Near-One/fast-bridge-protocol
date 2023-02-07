use clap::{Parser, Subcommand};
use fast_bridge_common::TransferMessage;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};

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
    }
}
