import { initContract, login, logout, deposit, withdraw, lock, lp_unlock } from './utils'


// `nearInitPromise` gets called on page load
window.nearInitPromise = initContract()
    .then(flow)
    .catch(console.error)

// Log in and log out users using NEAR Wallet
document.querySelector('.sign-in .btn').onclick = login;
document.querySelector('.sign-out .btn').onclick = logout;
document.querySelector('.deposit .btn').onclick = deposit;
document.querySelector('.withdraw .btn').onclick = withdraw;
document.querySelector('.lock .btn').onclick = lock;
document.querySelector('.lp-unlock .btn').onclick = lp_unlock;

function flow(){
  console.log("Contract initialize");
}




