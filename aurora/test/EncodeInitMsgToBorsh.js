const borsh = require("borsh");

function encodeInitMsgToBorsh(validTill, tokenNear, tokenEth, amount, amountFee, recipient, auroraSender) {
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
                    ["validTill", "u64"],
                    ["transfer", TransferStruct],
                    ["fee", FeeStruct],
                    ["recipient", [20]],
                    ["validTillBlockHeight", { kind: "option", type: "u64" }],
                    ["auroraSender", {kind: "option", type: [20]}],
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
                    ["tokenNear", "String"],
                    ["tokenEth", [20]],
                    ["amount", "u128"],
                ],
            },
        ],
    ]);

    const feeStruct = new FeeStruct({
        amount: amountFee,
        token: tokenNear.toString(),
    });

    const hexToBytes = (hex) => {
        var bytes = [];

        for (var c = 0; c < hex.length; c += 2) {
            bytes.push(parseInt(hex.substr(c, 2), 16));
        }

        return bytes;
    };

    const transferStruct = new TransferStruct({
        tokenNear: tokenNear,
        tokenEth:  hexToBytes(tokenEth),
        amount: amountFee.toString(),});

    const msgStruct = new MsgStruct({
        validTill: validTill.toString(),
        transfer: transferStruct,
        fee: feeStruct,
        recipient: hexToBytes(recipient.substring(2)),
        validTillBlockHeight: null,
        auroraSender: hexToBytes(auroraSender.substring(2)),
    });

    const msgBorsh = borsh.serialize(schema, msgStruct);
    return "0x" + Buffer.from(msgBorsh).toString('hex');
}

exports.encodeInitMsgToBorsh = encodeInitMsgToBorsh;