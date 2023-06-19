const borsh = require("borsh");

function encode_init_msg_to_borsh(valid_till, token_near, token_eth, amount, amount_fee, recipient, aurora_sender) {
    class MsgStruct {
        constructor(args) {
            Object.assign(this, args)
        }
    }
    class FeeStruct {
        constructor(args) {
            Object.assign(this, args)
        }
    }
    class TransferStruct {
        constructor(args) {
            Object.assign(this, args)
        }
    }

    const schema = new Map([
        [
            MsgStruct,
            {
                kind: "struct",
                fields: [
                    ["valid_till", "u64"],
                    ["transfer", TransferStruct],
                    ["fee", FeeStruct],
                    ["recipient", [20]],
                    ["valid_till_block_height", { kind: "option", type: "u64" }],
                    ["aurora_sender", {kind: "option", type: [20]}],
                ],
            },
        ],
        [
            FeeStruct,
            {
                kind: "struct",
                fields: [
                    ["token", "String"],
                    ["amount", "u128"],
                ],
            },
        ],
        [
            TransferStruct,
            {
                kind: "struct",
                fields: [
                    ["token_near", "String"],
                    ["token_eth", [20]],
                    ["amount", "u128"],
                ],
            },
        ],
    ]);

    const feeStruct = new FeeStruct({
        amount: amount_fee,
        token: token_near.toString(),
    });

    const hexToBytes = (hex) => {
        var bytes = [];

        for (var c = 0; c < hex.length; c += 2) {
            bytes.push(parseInt(hex.substr(c, 2), 16));
        }

        return bytes;
    };

    const transferStruct = new TransferStruct({
        token_near: token_near,
        token_eth:  hexToBytes(token_eth),
        amount: amount_fee.toString(),});

    const msgStruct = new MsgStruct({
        valid_till: valid_till.toString(),
        transfer: transferStruct,
        fee: feeStruct,
        recipient: hexToBytes(recipient.substring(2)),
        valid_till_block_height: null,
        aurora_sender: hexToBytes(aurora_sender.substring(2)),
    });

    const msgBorsh = borsh.serialize(schema, msgStruct);
    return "0x" + Buffer.from(msgBorsh).toString('hex');
}

exports.encode_init_msg_to_borsh = encode_init_msg_to_borsh;