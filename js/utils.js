import { connect, Contract, keyStores, WalletConnection } from 'near-api-js'
import getConfig from './config'
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

export async function deposit(accountId, amount){
    let rAmount = await window.contract.ft_on_transfer({args:{accountId,amount}})
        .catch(err => errorHelper(err))
    if(rAmount){
        console.warn('Some error with transaction, you tokens was not deposit.')
    }
    return rAmount;
}

export async function withdraw(nonce){
    await window.contract.unlock({args:{nonce}})
        .catch(err => errorHelper(err))
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
        console.warn('NEAR Warning: the contract/account seems to have state that is not (or no longer) compatible.\n' +
            'This may require deleting and recreating the NEAR account as shown here:\n' +
            'https://stackoverflow.com/a/60767144/711863');
    }
    if (err.message.includes('Cannot deserialize the contract state')) {
        console.warn('NEAR Warning: the contract/account seems to have state that is not (or no longer) compatible.\n' +
            'This may require deleting and recreating the NEAR account as shown here:\n' +
            'https://stackoverflow.com/a/60767144/711863');
    }
    console.error(err);
}