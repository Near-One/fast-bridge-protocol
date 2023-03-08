pragma solidity ^0.8.17;

import {IERC20 as IERC20_NEAR} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import "../lib/aurora-engine/etc/eth-contracts/contracts/EvmErc20.sol";
import {AuroraSdk, NEAR, PromiseCreateArgs, PromiseResultStatus, PromiseWithCallback} from "../lib/aurora-contracts-sdk/aurora-solidity-sdk/src/AuroraSdk.sol";
import "../lib/aurora-contracts-sdk/aurora-solidity-sdk/src/Borsh.sol";
import "../lib/aurora-contracts-sdk/aurora-solidity-sdk/src/Utils.sol";
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
    event Unlock(
        uint128 nonce,
        address sender,
        string token,
        uint128 amount
    );
    event SetWhitelistedUsers(
        address[] users,
        bool[] states
    );
    event TokenRegistered(
        address aurora_address,
        string near_address
    );
    event Withdraw(
        address recipient,
        string token,
        uint128 amount
    );
    event WithdrawFromNear(
        string token,
        uint128 amount
    );
    event InitTokenTransfer(
        address sender,
        string init_transfer_arg,
        string token,
        uint128 transfer_amount,
        uint128 fee_amount,
        address recipient
    );
    event InitTokenTransferRevert(
        address sender,
        string init_transfer_arg,
        string token,
        uint128 transfer_amount,
        uint128 fee_amount,
        address recipient
    );

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

        emit SetWhitelistedUsers(users, states);
    }

    function tokens_registration(address aurora_token_address, string memory near_token_address) public onlyRole(ADMIN) {
        emit NearContractInit(string(get_near_address()));

        uint128 deposit = 12_500_000_000_000_000_000_000;
        near.wNEAR.transferFrom(msg.sender, address(this), uint256(deposit));
        bytes memory args = bytes(string.concat('{"account_id": "', string(get_near_address()), '", "registreation_only": true }'));

        registered_tokens[near_token_address] = EvmErc20(aurora_token_address);
        PromiseCreateArgs memory callInc = near.call(near_token_address, "storage_deposit", args, deposit, BASE_NEAR_GAS);
        callInc.transact();

        emit TokenRegistered(aurora_token_address, near_token_address);
    }

    function withdraw(string memory token) public {
        uint128 signer_balance = balance[token][msg.sender];

        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));
        bytes memory args = bytes(string.concat('{"receiver_id": "aurora", "amount": "', Strings.toString(signer_balance), '", "msg": "', address_to_string(msg.sender), '"}'));
        PromiseCreateArgs memory callTr = near.call(token, "ft_transfer_call", args, 1, BASE_NEAR_GAS);
        callTr.transact();

        balance[token][msg.sender] = 0;
        emit Withdraw(msg.sender, token, signer_balance);
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
        borsh.decodeBytes20(); //recipient
        uint8 option_valid_till = borsh.decodeU8();
        if (option_valid_till == 1) {
            borsh.decodeU64();//valid_till_block_height
        }
        uint8 option_aurora_sender = borsh.decodeU8();
        require(option_aurora_sender == 1, "Aurora sender not present in Transfer Message!");
        address aurora_sender = address(borsh.decodeBytes20());
        require(aurora_sender == msg.sender, "Aurora sender in transfer message doesn't equal to signer");

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
        address recipient = address(borsh.decodeBytes20());

        balance[token_address_on_near][signer] += (transfer_token_amount + fee_token_amount - transferred_amount);

        string memory init_args_base64 = Base64.encode(init_transfer_args);
        if (transferred_amount == 0) {
            emit InitTokenTransferRevert(signer, init_args_base64, token_address_on_near, transfer_token_amount, fee_token_amount, recipient);
        } else {
            emit InitTokenTransfer(signer, init_args_base64, token_address_on_near, transfer_token_amount, fee_token_amount, recipient);
        }
    }

    function withdraw_from_near(string memory token_id, uint128 amount) public {
        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));

        bytes memory args = bytes(string.concat('{"token_id": "', token_id, '", "amount": "', Strings.toString(amount), '"}'));
        PromiseCreateArgs memory callTr = near.call(bridge_address_on_near, "withdraw", args, 1, BASE_NEAR_GAS);
        callTr.transact();

        emit WithdrawFromNear(token_id, amount);
    }

    function unlock(uint128 nonce) public {
        bytes memory args = bytes(string.concat('{"nonce": "', Strings.toString(nonce), '", "aurora_sender": "', address_to_string(msg.sender) ,'"}'));

        PromiseCreateArgs memory callTr = near.call(bridge_address_on_near, "unlock", args, 0, INIT_TRANSFER_NEAR_GAS);
        bytes memory callback_arg = abi.encodeWithSelector(this.unlock_callback.selector, msg.sender, nonce);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callback_arg, 0, BASE_NEAR_GAS);

        callTr.then(callback).transact();
    }

    function unlock_callback(address signer, uint128 nonce) public onlyRole(CALLBACK_ROLE) {
        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            Borsh.Data memory borsh = Borsh.from(AuroraSdk.promiseResult(0).output);
            borsh.decodeU64(); //valid_till
            string memory token_address_on_near = string(borsh.decodeBytes()); //transfer token address on Near
            borsh.decodeBytes20(); //transfer token address on Ethereum
            uint128 transfer_token_amount = borsh.decodeU128();
            borsh.decodeBytes(); // fee token address on Near
            uint128 fee_token_amount = borsh.decodeU128();

            balance[token_address_on_near][signer] += (transfer_token_amount + fee_token_amount);
            emit Unlock(nonce, signer, token_address_on_near, transfer_token_amount + fee_token_amount);
        }
    }

    function get_near_address() public view returns (bytes memory) {
        string memory aurora_address = address_to_string(address(this));
        return bytes(string.concat(aurora_address, ".aurora"));
    }

    function address_to_string(address aurora_address) private pure returns (string memory) {
        return Utils.bytesToHex(abi.encodePacked(aurora_address));
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
