import "regenerator-runtime/runtime";
import { initContract, login, logout } from './near/utils'


// `nearInitPromise` gets called on page load
window.nearInitPromise = initContract()
    .then(flow)
    .catch(console.error)

function flow(){
    //TODO: action after contract was init
}
