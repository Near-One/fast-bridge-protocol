import {initContract, login, logout, deposit, withdraw, lock, unlock} from './src/spectre-bridge-client.js'


// `nearInitPromise` gets called on page load
window.nearInitPromise = initContract()
    .then(flow)
    .catch(console.error)

// Log in and log out users using NEAR Wallet
document.querySelector('.sign-in').onclick = login;
document.querySelector('.sign-out').onclick = logout;
document.querySelector('.deposit').onclick = function () {
    let token = document.querySelector('.account-id').value;
    let amount = document.querySelector('.deposit-amount').value;
    let msg = document.querySelector('.msg').value;
    deposit(token, amount, msg);
}
document.querySelector('.unlock').onclick = function () {
    let nonce = parseInt(document.querySelector('.unlock-nonce').value);
    unlock(nonce);
}
document.querySelector('.withdraw').onclick = function () {
    let receiver = document.querySelector('.receiver-account-id').value;
    let amount = document.querySelector('.withdraw-amount').value;
    withdraw(receiver, amount);
}
document.querySelector('.lock').onclick = function () {

    let valid_time = parseInt(document.querySelector('input.valid-time').value);
    let chain_id = parseInt(document.querySelector('#lock .chain-id').value);
    let tr_token_near = document.querySelector('#lock .transfer .token-near').value;
    let tr_token_eth = document.querySelector('#lock .transfer .token-eth').value.split(",").map(Number);
    let tr_amount = document.querySelector('#lock .transfer .amount').value;
    let fee_token = document.querySelector('#lock .fee .token-near').value;
    let fee_amount = document.querySelector('#lock .fee .amount').value;
    let recipient = document.querySelector('#lock .recipient').value.split(",").map(Number);

    let msg = {
        chain_id: chain_id,
        valid_till: valid_time,
        transfer: {
            token_near: tr_token_near,
            token_eth: tr_token_eth,
            amount: tr_amount
        },
        fee: {
            token: fee_token,
            amount: fee_amount
        },
        recipient: recipient
    };
    lock(JSON.stringify(msg));
}

document.querySelector('.autocomplete').onclick = function () {
    let timestamp = Date.now() / 0.000001 + 11900000000000;
    document.querySelector('input.valid-time').value = timestamp;
    document.querySelector('#lock .chain-id').value = 5;
    document.querySelector('#lock .transfer .token-near').value = "token.spectrebridge2.testnet";
    document.querySelector('#lock .transfer .token-eth').value = [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111];
    document.querySelector('#lock .transfer .amount').value = "2";
    document.querySelector('#lock .fee .token-near').value = "token.spectrebridge2.testnet";
    document.querySelector('#lock .fee .amount').value = "2";
    document.querySelector('#lock .recipient').value = [113, 199, 101, 110, 199, 171, 136, 176, 152, 222, 251, 117, 27, 116, 1, 181, 246, 216, 151, 111];
}
document.querySelector('.autocomplete-deposit').onclick = function () {
    document.querySelector('.account-id').value = "transfer.spectrebridge2.testnet";
    document.querySelector('.deposit-amount').value = "100";
    document.querySelector('.msg').value = "transfer 100 tokens to transfer.spectrebridge2.testnet";
}
document.querySelector('.set-auto').onclick = function () {
    let timestamp = Date.now() / 0.000001 + 11900000000000;
    document.querySelector('input.valid-time').value = timestamp;
}

function flow() {
    console.log("Contract initialize");
}




