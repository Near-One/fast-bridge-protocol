import {connect, Contract, keyStores, WalletConnection} from 'near-api-js'
import getConfig from './config.js'

const nearConfig = getConfig(process.env.NODE_ENV || 'development')

// Initialize contract & set global variables
export async function initContract() {
    const near = await connect(Object.assign({deps: {keyStore: new keyStores.BrowserLocalStorageKeyStore()}}, nearConfig))
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

export async function deposit(accountId, amount) {
    await window.contract.ft_on_transfer({args: {token_id: accountId, amount: amount}})
        .catch(err => errorHelper(err))
}

export async function withdraw(nonce) {
    await window.contract.unlock({args: {nonce: nonce}})
        .catch(err => errorHelper(err))
}

export async function lock(msg) {
    await window.contract.lock({args: {msg: msg}})
        .catch(err => errorHelper(err))
}

export async function lp_unlock(nonce, proof) {
    await window.contract.lp_unlock({args: {nonce: nonce, proof: proof}})
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