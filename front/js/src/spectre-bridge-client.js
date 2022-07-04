import {connect, Contract, keyStores, WalletConnection} from 'near-api-js'
import getConfig from './config.js'

const nearConfig = getConfig(process.env.NODE_ENV || 'development')

// Initialize contract & set global variables
export async function initContract() {
    const near = await connect(Object.assign({deps: {keyStore: new keyStores.BrowserLocalStorageKeyStore()}}, nearConfig))
    window.walletConnection = new WalletConnection(near)
    window.accountId = window.walletConnection.getAccountId()
    window.contract = await new Contract(window.walletConnection.account(), nearConfig.contractName, {
        changeMethods: ['ft_on_transfer', 'lock', 'unlock', 'lp_unlock', 'withdraw'],
    });
    window.contract2 = await new Contract(window.walletConnection.account(), nearConfig.tokenContractName, {
        changeMethods: ['ft_transfer_call'],
    })
}

export function logout() {
    window.walletConnection.signOut()
    window.location.replace(window.location.origin + window.location.pathname)
}

export function login() {
    window.walletConnection.requestSignIn(nearConfig.contractName)
}

export async function deposit(accountId, amount, msg) {
    await window.contract2.ft_transfer_call({
        args: {receiver_id: accountId, amount: amount, msg: msg},
        gas: "300000000000000",
        amount: "1"
    })
        .catch(err => errorHelper(err))
}

export async function unlock(nonce) {
    await window.contract.unlock({
        args: {nonce: nonce},
        gas: "300000000000000",
    })
        .catch(err => errorHelper(err))
}

export async function withdraw(token_id, amount) {
    await window.contract.withdraw({
        args: {token_id: token_id, amount: amount},
        gas: "300000000000000",
        amount: "1"
    })
        .catch(err => errorHelper(err))
}

export async function lock(msg) {
    await window.contract.lock({
        args: {msg: msg},
        gas: "300000000000000"
    })
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