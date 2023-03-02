pragma solidity ^0.8.17;

import {IERC20 as IERC20_NEAR} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import "../lib/aurora-engine/etc/eth-contracts/contracts/EvmErc20.sol";
import {AuroraSdk, NEAR, PromiseCreateArgs, PromiseResultStatus, PromiseWithCallback} from "../lib/aurora-contracts-sdk/aurora-solidity-sdk/src/AuroraSdk.sol";
import "../lib/aurora-contracts-sdk/aurora-solidity-sdk/src/Borsh.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

uint64 constant BASE_NEAR_GAS = 50_000_000_000_000;
uint64 constant INIT_TRANSFER_NEAR_GAS = 100_000_000_000_000;

contract AuroraErc20FastBridge is AccessControl {
    using AuroraSdk for NEAR;
    using AuroraSdk for PromiseCreateArgs;
    using AuroraSdk for PromiseWithCallback;
    using Borsh for Borsh.Data;

    bytes32 public constant ADMIN = keccak256("ADMIN");
    bytes32 public constant CALLBACK_ROLE = keccak256("CALLBACK_ROLE");

    address creator;
    NEAR public near;
    string bridge_address_on_near;

    mapping(address => bool) whitelisted_users;
    mapping(string => EvmErc20) registered_tokens;
    mapping(string => mapping(address => uint128)) balance;

    event NearContractInit(string near_addres);

    constructor(address wnear_address, string memory bridge_address) {
        creator = msg.sender;
        near = AuroraSdk.initNear(IERC20_NEAR(wnear_address));
        bridge_address_on_near = bridge_address;

        _grantRole(CALLBACK_ROLE, AuroraSdk.nearRepresentitiveImplicitAddress(address(this)));
        _grantRole(ADMIN, msg.sender);

        whitelisted_users[msg.sender] = true;
    }

    function setWhitelistedUsers(address[] memory users, bool[] memory states) public onlyRole(ADMIN) {
        require(users.length == states.length, "Arrays must be equal");

        for (uint256 i = 0; i < users.length; i++) {
            whitelisted_users[users[i]] = states[i];
        }
    }

    function tokens_registration(address aurora_token_address, string memory near_token_address) public onlyRole(ADMIN) {
        emit NearContractInit(string(get_near_address()));

        uint128 deposit = 12_500_000_000_000_000_000_000;
        near.wNEAR.transferFrom(msg.sender, address(this), uint256(deposit));
        bytes memory args = bytes(string.concat('{"account_id": "', string(get_near_address()), '", "registreation_only": true }'));

        registered_tokens[near_token_address] = EvmErc20(aurora_token_address);
        PromiseCreateArgs memory callInc = near.call(near_token_address, "storage_deposit", args, deposit, BASE_NEAR_GAS);
        callInc.transact();
    }

    function withdraw(string memory token) public {
        uint128 signer_balance = balance[token][msg.sender];

        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));
        bytes memory args = bytes(string.concat('{"receiver_id": "aurora", "amount": "', Strings.toString(signer_balance), '", "msg": "', string(address_to_string(address(msg.sender))), '"}'));
        PromiseCreateArgs memory callTr = near.call(token, "ft_transfer_call", args, 1, BASE_NEAR_GAS);
        callTr.transact();

        balance[token][msg.sender] = 0;
    }

    function init_token_transfer(bytes memory init_transfer_args) public {
        require(whitelisted_users[address(msg.sender)], "Sender not whitelisted!");

        Borsh.Data memory borsh = Borsh.from(init_transfer_args);
        borsh.decodeU64(); //valid_till
        string memory token_address_on_near = string(borsh.decodeBytes()); //transfer token address on Near
        borsh.decodeBytes20(); //transfer token address on Ethereum
        uint128 transfer_token_amount = borsh.decodeU128();
        string memory fee_token_address_on_near = string(borsh.decodeBytes()); // fee token address on Near
        uint128 fee_token_amount = borsh.decodeU128();

        require(keccak256(abi.encodePacked(token_address_on_near)) == keccak256(abi.encodePacked(fee_token_address_on_near)));

        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));

        EvmErc20 token = registered_tokens[token_address_on_near];
        token.transferFrom(msg.sender, address(this), uint256(transfer_token_amount + fee_token_amount));
        token.withdrawToNear(get_near_address(), uint256(transfer_token_amount + fee_token_amount));

        string memory init_args_base64 = Base64.encode(init_transfer_args);
        bytes memory args = bytes(string.concat('{"receiver_id": "', bridge_address_on_near, '", "amount": "', Strings.toString(transfer_token_amount + fee_token_amount), '", "msg": "', init_args_base64, '"}'));

        PromiseCreateArgs memory callTr = near.call(token_address_on_near, "ft_transfer_call", args, 1, INIT_TRANSFER_NEAR_GAS);
        bytes memory callback_arg = abi.encodeWithSelector(this.init_token_transfer_callback.selector, msg.sender, init_transfer_args);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callback_arg, 0, BASE_NEAR_GAS);

        callTr.then(callback).transact();
    }

    function init_token_transfer_callback(address signer, bytes memory init_transfer_args) public onlyRole(CALLBACK_ROLE) {
        uint128 transferred_amount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferred_amount = stringToUint(AuroraSdk.promiseResult(0).output);
        }

        Borsh.Data memory borsh = Borsh.from(init_transfer_args);
        borsh.decodeU64(); //valid_till
        string memory token_address_on_near = string(borsh.decodeBytes()); //transfer token address on Near
        borsh.decodeBytes20(); //transfer token address on Ethereum
        uint128 transfer_token_amount = borsh.decodeU128();
        borsh.decodeBytes(); // fee token address on Near
        uint128 fee_token_amount = borsh.decodeU128();

        balance[token_address_on_near][signer] += (transfer_token_amount + fee_token_amount - transferred_amount);
    }

    function get_near_address() public view returns (bytes memory) {
        bytes memory aurora_address = address_to_string(address(this));
        return bytes(string.concat(string(aurora_address), ".aurora"));
    }

    function address_to_string(address aurora_address) private pure returns (bytes memory) {
        bytes memory address_raw = bytes(Strings.toHexString(uint160(aurora_address)));
        bytes memory address_str = new bytes(address_raw.length - 2);

        for (uint256 i = 0; i < address_raw.length - 2; ++i) {
            address_str[i] = address_raw[i + 2];
        }

        return address_str;
    }

    function stringToUint(bytes memory b) private pure returns (uint128) {
        uint128 result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            uint128 c = uint128(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
        return result;
    }

    function destruct() public {
        // Destroys this contract and sends remaining funds back to creator
        if (msg.sender == creator)
            selfdestruct(payable(creator));
    }
}
