const { ethers } = require('hardhat');
const Web3 = require("web3");
const {Header, Account} = require('eth-object');
const _utils = require('ethereumjs-util');
const borsh = require('borsh')

const provider = new ethers.providers.JsonRpcProvider('https://ethereum-goerli-rpc.allthatnode.com');
const web3 = new Web3(new Web3.providers.HttpProvider('https://ethereum-goerli-rpc.allthatnode.com'));

const mappingSlotNumber = 303;

function parseHexString(str) {
    var result = [];
    while (str.length >= 2) {
        result.push(parseInt(str.substring(0, 2), 16));
        str = str.substring(2, str.length);
    }

    return result;
}

function processedHash(_token, _recipient, _nonce, _amount) {
    let encodedData = ethers.utils.solidityPack(["address", "address", "uint256", "uint256"],[_token, _recipient, _nonce, _amount]);
    return ethers.utils.solidityKeccak256(["bytes"],[encodedData]);
}

function getProcessedHashSlotKey(processedHash){
    const paddedSlot = ethers.utils.hexZeroPad(mappingSlotNumber, 32);
    const paddedKey = ethers.utils.hexZeroPad(processedHash, 32);
    return ethers.utils.keccak256(paddedKey + paddedSlot.slice(2));
}

async function get_proof_of_data(contractAddress, slotKey, blockNumber) {
    return await web3.eth.getProof(contractAddress, [slotKey], blockNumber);
}

async function get_block_data(blockNumber) {
    return await web3.eth.getBlock(blockNumber);
}

async function generate_unlock_proof(getProof_response, block){
    let header_rlp = (Header.fromRpc(block).serialize()).toString('hex');
    let account_proof = getProof_response.accountProof.map((proof_data) => (parseHexString(_utils.toBuffer(proof_data).toString('hex'))));  //converts to bytes array of account proof
    let res = getProof_response;
    res.nonce = web3.utils.toHex(res.nonce);   // done for fixing error in eth-object for Account
    res.balance = web3.utils.toHex(res.balance);  // done for fixing error in eth-object for Account
    let account_data = (Account.fromRpc(res).serialize()).toString('hex');
    console.log("getProof_response: ", getProof_response);
    let storage_proof = getProof_response.storageProof[0].proof.map((proof_data) => (parseHexString(_utils.toBuffer(proof_data).toString('hex'))));

    console.log("header data:", header_rlp);

    const unlockProof = {
        header_data: parseHexString(header_rlp),
        account_proof: account_proof,
        account_data: parseHexString(account_data),
        storage_proof: storage_proof,
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

async function get_unlock_proof(contractAddress, data, blockNumber) {
    let processHash = processedHash(data.token, data.recipient, data.nonce, data.amount);
    let slotKeyOfProcessedHash = getProcessedHashSlotKey(processHash);
    let response_data = await get_proof_of_data(contractAddress, slotKeyOfProcessedHash, blockNumber);
    let block = await get_block_data(blockNumber);
    block.difficulty = web3.utils.toHex(block.difficulty);
    console.log(block);
    let unlock_proof = await generate_unlock_proof(response_data, block);

    let borsh_ser = borsh.serialize(
        new Map([[Test, {kind: 'struct',
            fields: [['header_data', ['u8']],
            ['account_proof', [['u8']]],
            ['account_data', ['u8']],
            ['storage_proof', [['u8']]]]}]]), new Test(unlock_proof));
    return borsh_ser.toString("base64");
}

exports.get_unlock_proof = get_unlock_proof;