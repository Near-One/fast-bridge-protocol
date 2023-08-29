const { ethers } = require("hardhat");
const { Web3, Web3RequestManager } = require("web3");
const {Header, Account} = require('eth-object');
const _utils = require('ethereumjs-util');
const borsh = require('borsh')

const provider = new ethers.getDefaultProvider('https://ethereum-goerli-rpc.allthatnode.com');
const web3 = new Web3('https://ethereum-goerli-rpc.allthatnode.com');

const mappingSlotNumber = 302;

function parseHexString(str) {
    var result = [];
    while (str.length >= 2) {
        result.push(parseInt(str.substring(0, 2), 16));
        str = str.substring(2, str.length);
    }

    return result;
}

function processedHash(_token, _recipient, _nonce, _amount) {
    let encodedData = ethers.solidityPacked(["address", "address", "uint256", "uint256"],[_token, _recipient, _nonce, _amount]);
    return ethers.solidityPackedKeccak256(["bytes"],[encodedData]);
}

function getProcessedHashSlotKey(processedHash){
    const paddedSlot = ethers.zeroPadValue(ethers.toBeArray(mappingSlotNumber), 32);
    console.log("Padding slot:", paddedSlot);
    const paddedKey = ethers.zeroPadValue(processedHash, 32);
    console.log("Padding key:", paddedKey);
    return ethers.keccak256(paddedKey + paddedSlot.slice(2));
}

async function getProofOfData(contractAddress, slotKey, blockNumber) {
    return await web3.eth.getProof(contractAddress, [slotKey], blockNumber);
}

async function getBlockData(blockNumber) {
    return await web3.eth.getBlock(blockNumber);
}

async function generateUnlockProof(getProofResponse, block){
    console.log("block", block);
    let headerRlp = (Header.fromRpc(block).serialize()).toString("hex");
    console.log("header: ", Header.fromRpc(block));
    let accountProof = getProofResponse.accountProof.map((proof_data) => (parseHexString(_utils.toBuffer(proof_data).toString('hex'))));  //converts to bytes array of account proof
    let res = getProofResponse;
    res.nonce = web3.utils.toHex(res.nonce);   // done for fixing error in eth-object for Account
    res.balance = web3.utils.toHex(res.balance);  // done for fixing error in eth-object for Account
    let accountData = (Account.fromRpc(res).serialize()).toString('hex');
    console.log("getProof_response: ", getProofResponse);
    let storageProof = getProofResponse.storageProof[0].proof.map((proof_data) => (parseHexString(_utils.toBuffer(proof_data).toString('hex'))));

    console.log("header data:", headerRlp);

    console.log("account_data:", accountData);

    for (let i = 0; i  < accountProof.length; ++i) {
        console.log("account_proof:", accountProof[i].toString());
    }

    for (let i = 0; i < storageProof.length; ++i) {
        console.log("storage_proof:", storageProof[i].toString());
    }

    const unlockProof = {
        header_data: parseHexString(headerRlp),
        account_proof: accountProof,
        account_data: parseHexString(accountData),
        storage_proof: storageProof,
    }

    return unlockProof;
}

class Assignable {
    constructor(properties) {
        Object.keys(properties).map((key) => {
            this[key] = properties[key];
        });
    }
}

class Test extends Assignable { }

async function getUnlockProof(contractAddress, data, blockNumber) {
    let processHash = processedHash(data.token, data.recipient, data.nonce, data.amount);
    let slotKeyOfProcessedHash = getProcessedHashSlotKey(processHash);
    console.log("Stroage key: ", slotKeyOfProcessedHash);
    let responseData = await getProofOfData(contractAddress, slotKeyOfProcessedHash, blockNumber);
    let block = await getBlockData(blockNumber);
    block.difficulty = web3.utils.toHex(block.difficulty);
    console.log("block", block);
    console.log(block.number.toString(16));
    console.log(typeof block.number);
    block.number = parseInt(block.number);
    block.nonce = "0x0000000000000000";//parseInt(block.nonce).toString(16);
    block.baseFeePerGas = parseInt(block.baseFeePerGas);
    block.gasLimit = parseInt(block.gasLimit);
    block.gasUsed = "0x0";// parseInt(block.gasUsed);
    block.size = parseInt(block.size);
    block.timestamp = parseInt(block.timestamp);
    block.totalDifficulty = parseInt(block.totalDifficulty);
    block.withdrawalsRoot = "0xb2c385352467131eec9f3920d29ec5b49fd20dce7c9b24ffab69413a606aa7b7"
    console.log(typeof block.number);
    
    let unlockProof = await generateUnlockProof(responseData, block);

    console.log("unlock Proof: ", unlockProof);

    let borshSer = borsh.serialize(
        new Map([[Test, {kind: 'struct',
            fields: [['header_data', ['u8']],
            ['account_proof', [['u8']]],
            ['account_data', ['u8']],
            ['storage_proof', [['u8']]]]}]]), new Test(unlockProof));
    return borshSer.toString("base64");
}

exports.getUnlockProof = getUnlockProof;
