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
uint64 constant UNLOCK_NEAR_GAS = 100_000_000_000_000;

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

    //The Whitelisted Aurora users which allowed use fast bridge.
    mapping(address => bool) whitelisted_users;
    //By the token address on near returns correspondent ERC20 Aurora token.
    //[token_address_on_near] => aurora_erc20_token
    mapping(string => EvmErc20) registered_tokens;
    //By the token account id on near and user address on aurora return the user balance of this token in this contract
    //[token_address_on_near][user_address_on_aurora] => user_token_balance_in_aurora_fast_bridge
    mapping(string => mapping(address => uint128)) balance;

    event Unlock(
        uint128 nonce,
        address sender,
        string transfer_token,
        uint128 transfer_amount,
        string fee_token,
        uint128 fee_amount
    );
    event SetWhitelistedUsers(address[] users, bool[] states);
    event TokenRegistered(address aurora_address, string near_address);
    event Withdraw(address recipient, string token, uint128 amount);
    event WithdrawFromNear(string token, uint128 amount);
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

    struct TransferMessage {
        uint64 valid_till;
        string transfer_token_address_on_near;
        address transfer_token_address_on_eth;
        uint128 transfer_token_amount;
        string fee_token_address_on_near;
        uint128 fee_token_amount;
        address recipient;
        uint64 valid_till_block_height;
        address aurora_sender;
    }

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

    function tokens_registration(
        address aurora_token_address,
        string memory near_token_address
    ) public onlyRole(ADMIN) {
        uint128 deposit = 12_500_000_000_000_000_000_000;
        near.wNEAR.transferFrom(msg.sender, address(this), uint256(deposit));
        bytes memory args = bytes(
            string.concat('{"account_id": "', get_near_address(), '", "registreation_only": true }')
        );

        PromiseCreateArgs memory callInc = near.call(
            near_token_address,
            "storage_deposit",
            args,
            deposit,
            BASE_NEAR_GAS
        );
        callInc.transact();

        registered_tokens[near_token_address] = EvmErc20(aurora_token_address);
        emit TokenRegistered(aurora_token_address, near_token_address);
    }

    function init_token_transfer(bytes memory init_transfer_args) public {
        require(whitelisted_users[address(msg.sender)], "Sender not whitelisted!");
        TransferMessage memory transfer_message = decode_transfer_message_from_borsh(init_transfer_args);
        require(
            transfer_message.aurora_sender == msg.sender,
            "Aurora sender in transfer message doesn't equal to signer"
        );
        require(
            keccak256(abi.encodePacked(transfer_message.transfer_token_address_on_near)) ==
                keccak256(abi.encodePacked(transfer_message.fee_token_address_on_near))
        );

        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));

        uint256 total_token_amount = uint256(
            transfer_message.transfer_token_amount + transfer_message.fee_token_amount
        );

        EvmErc20 token = registered_tokens[transfer_message.transfer_token_address_on_near];
        token.transferFrom(msg.sender, address(this), total_token_amount);
        token.withdrawToNear(bytes(get_near_address()), total_token_amount);

        string memory init_args_base64 = Base64.encode(init_transfer_args);
        bytes memory args = bytes(
            string.concat(
                '{"receiver_id": "',
                bridge_address_on_near,
                '", "amount": "',
                Strings.toString(total_token_amount),
                '", "msg": "',
                init_args_base64,
                '"}'
            )
        );

        PromiseCreateArgs memory callTr = near.call(
            transfer_message.transfer_token_address_on_near,
            "ft_transfer_call",
            args,
            1,
            INIT_TRANSFER_NEAR_GAS
        );
        bytes memory callback_arg = abi.encodeWithSelector(
            this.init_token_transfer_callback.selector,
            msg.sender,
            init_transfer_args
        );
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callback_arg, 0, BASE_NEAR_GAS);

        callTr.then(callback).transact();
    }

    function init_token_transfer_callback(
        address signer,
        bytes memory init_transfer_args
    ) public onlyRole(CALLBACK_ROLE) {
        uint128 transferred_amount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferred_amount = stringToUint(AuroraSdk.promiseResult(0).output);
        }

        TransferMessage memory transfer_message = decode_transfer_message_from_borsh(init_transfer_args);

        balance[transfer_message.transfer_token_address_on_near][signer] += (transfer_message.transfer_token_amount +
            transfer_message.fee_token_amount -
            transferred_amount);

        string memory init_args_base64 = Base64.encode(init_transfer_args);
        if (transferred_amount == 0) {
            emit InitTokenTransferRevert(
                signer,
                init_args_base64,
                transfer_message.transfer_token_address_on_near,
                transfer_message.transfer_token_amount,
                transfer_message.fee_token_amount,
                transfer_message.recipient
            );
        } else {
            emit InitTokenTransfer(
                signer,
                init_args_base64,
                transfer_message.transfer_token_address_on_near,
                transfer_message.transfer_token_amount,
                transfer_message.fee_token_amount,
                transfer_message.recipient
            );
        }
    }

    function unlock(uint128 nonce) public {
        bytes memory args = bytes(
            string.concat(
                '{"nonce": "',
                Strings.toString(nonce),
                '", "aurora_sender": "',
                address_to_string(msg.sender),
                '"}'
            )
        );

        PromiseCreateArgs memory callTr = near.call(bridge_address_on_near, "unlock", args, 0, UNLOCK_NEAR_GAS);
        bytes memory callback_arg = abi.encodeWithSelector(this.unlock_callback.selector, msg.sender, nonce);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callback_arg, 0, BASE_NEAR_GAS);

        callTr.then(callback).transact();
    }

    function unlock_callback(address signer, uint128 nonce) public onlyRole(CALLBACK_ROLE) {
        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            TransferMessage memory transfer_message = decode_transfer_message_from_borsh(
                AuroraSdk.promiseResult(0).output
            );

            balance[transfer_message.transfer_token_address_on_near][signer] += transfer_message.transfer_token_amount;
            balance[transfer_message.fee_token_address_on_near][signer] += transfer_message.fee_token_amount;

            emit Unlock(
                nonce,
                signer,
                transfer_message.transfer_token_address_on_near,
                transfer_message.transfer_token_amount,
                transfer_message.fee_token_address_on_near,
                transfer_message.fee_token_amount
            );
        }
    }

    function withdraw_from_near(string memory token_id, uint128 amount) public {
        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));

        bytes memory args = bytes(
            string.concat('{"token_id": "', token_id, '", "amount": "', Strings.toString(amount), '"}')
        );
        PromiseCreateArgs memory call_withdraw = near.call(bridge_address_on_near, "withdraw", args, 1, BASE_NEAR_GAS);
        bytes memory callback_arg = abi.encodeWithSelector(this.withdraw_from_near_callback.selector, token_id, amount);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callback_arg, 0, BASE_NEAR_GAS);

        call_withdraw.then(callback).transact();
    }

    function withdraw_from_near_callback(string memory token_id, uint128 amount) public onlyRole(CALLBACK_ROLE) {
        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            emit WithdrawFromNear(token_id, amount);
        }
    }

    function withdraw(string memory token) public {
        uint128 signer_balance = balance[token][msg.sender];

        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));
        bytes memory args = bytes(
            string.concat(
                '{"receiver_id": "aurora", "amount": "',
                Strings.toString(signer_balance),
                '", "msg": "',
                address_to_string(msg.sender),
                '"}'
            )
        );
        PromiseCreateArgs memory call_withdraw = near.call(token, "ft_transfer_call", args, 1, BASE_NEAR_GAS);
        bytes memory callback_arg = abi.encodeWithSelector(this.withdraw_callback.selector, msg.sender, token);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callback_arg, 0, BASE_NEAR_GAS);

        call_withdraw.then(callback).transact();
    }

    function withdraw_callback(address signer, string memory token) public onlyRole(CALLBACK_ROLE) {
        uint128 transferred_amount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferred_amount = stringToUint(AuroraSdk.promiseResult(0).output);
        }

        if (transferred_amount > 0) {
            balance[token][signer] -= transferred_amount;
            emit Withdraw(signer, token, transferred_amount);
        }
    }

    function decode_transfer_message_from_borsh(
        bytes memory transfer_message_borsh
    ) private pure returns (TransferMessage memory) {
        TransferMessage memory result;
        Borsh.Data memory borsh = Borsh.from(transfer_message_borsh);
        result.valid_till = borsh.decodeU64();
        result.transfer_token_address_on_near = string(borsh.decodeBytes()); //transfer token address on Near
        result.transfer_token_address_on_eth = address(borsh.decodeBytes20()); //transfer token address on Ethereum
        result.transfer_token_amount = borsh.decodeU128();
        result.fee_token_address_on_near = string(borsh.decodeBytes()); // fee token address on Near
        result.fee_token_amount = borsh.decodeU128();
        result.recipient = address(borsh.decodeBytes20()); //recipient
        uint8 option_valid_till = borsh.decodeU8();
        if (option_valid_till == 1) {
            result.valid_till_block_height = borsh.decodeU64(); //valid_till_block_height
        }
        uint8 option_aurora_sender = borsh.decodeU8();
        if (option_aurora_sender == 1) {
            result.aurora_sender = address(borsh.decodeBytes20());
        }
        return result;
    }

    function get_near_address() public view returns (string memory) {
        string memory aurora_address = address_to_string(address(this));
        return string.concat(aurora_address, ".aurora");
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
        if (msg.sender == creator) selfdestruct(payable(creator));
    }
}
