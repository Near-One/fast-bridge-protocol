import { connect, Contract, keyStores, WalletConnection } from 'near-api-js'
import getConfig from './config.js'
const nearConfig = getConfig(process.env.NODE_ENV || 'development')

// Initialize contract & set global variables
export async function initContract() {

    const near = await connect(Object.assign({ deps: { keyStore: new keyStores.BrowserLocalStorageKeyStore() } }, nearConfig))
    window.walletConnection = new WalletConnection(near)
    window.accountId = window.walletConnection.getAccountId()
    window.contract = await new Contract(window.walletConnection.account(), nearConfig.contractName, {
        changeMethods: ['ft_on_transfer', 'lock', 'unlock', 'lp_unlock'],
    })
}

export function logout() {
    window.walletConnection.signOut()
    window.location.replace(window.location.origin + window.location.pathname)
}

export function login() {
    window.walletConnection.requestSignIn(nearConfig.contractName)
}

export async function deposit(){
    console.log("Deposit action run");
    var accountId = "token.spectrebridge2.testnet";
    var amount = 20;
    await window.contract.ft_on_transfer({args:{token_id:accountId,amount:amount}})
    .then(successDepositCallback,failureDepositCallback);
}

function successDepositCallback(result) {
    console.log("Amount after ft_on_transfer: " + result);
}

function failureDepositCallback(error) {
    console.log("Error: " + error);
}

export async function withdraw(){
    var nonce = 1;
    await window.contract. unlock({args:{nonce}})
        .then(successWithdrawCallback,failureWithdrawCallback);
}

function successWithdrawCallback(result) {
    console.log("Amount after unlock: " + result);
}

function failureWithdrawCallback(error) {
    console.log("Error: " + error);
}

export async function lock(msg){
    await window.contract.lock({args:{msg}})
        .catch(err => errorHelper(err))
}

export async function lp_unlock(proof){
    await window.contract.lp_unlock({args:{proof}})
        .catch(err => errorHelper(err))
}

function errorHelper(err) {
    if (err.message.includes('Cannot deserialize the contract state')) {
        console.warn('NEAR Warning: the contract/account seems to have state that is not (or no longer) compatible.');
    }
    if (err.message.includes('Cannot deserialize the contract state')) {
        console.warn('NEAR Warning: the contract/account seems to have state that is not (or no longer) compatible.');
    }
    console.error(err);
}