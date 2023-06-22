// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {IERC20 as IERC20_NEAR} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import "../lib/aurora-engine/etc/eth-contracts/contracts/EvmErc20.sol";
import {AuroraSdk, NEAR, PromiseCreateArgs, PromiseResultStatus, PromiseWithCallback} from "../lib/aurora-contracts-sdk/aurora-solidity-sdk/src/AuroraSdk.sol";
import "../lib/aurora-contracts-sdk/aurora-solidity-sdk/src/Borsh.sol";
import "../lib/aurora-contracts-sdk/aurora-solidity-sdk/src/Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

uint64 constant BASE_NEAR_GAS = 10_000_000_000_000;
uint64 constant WITHDRAW_NEAR_GAS = 50_000_000_000_000;
uint64 constant INIT_TRANSFER_NEAR_GAS = 100_000_000_000_000;
uint64 constant UNLOCK_NEAR_GAS = 150_000_000_000_000;

contract AuroraErc20FastBridge is AccessControl {
    using AuroraSdk for NEAR;
    using AuroraSdk for PromiseCreateArgs;
    using AuroraSdk for PromiseWithCallback;
    using Borsh for Borsh.Data;

    bytes32 public constant ADMIN = keccak256("ADMIN");
    bytes32 public constant CALLBACK_ROLE = keccak256("CALLBACK_ROLE");

    NEAR public near;
    string bridgeAddressOnNear;

    //The Whitelisted Aurora users which allowed use fast bridge.
    mapping(address => bool) whitelistedUsers;

    //By the token address on near returns correspondent ERC20 Aurora token.
    //[token_address_on_near] => aurora_erc20_token
    mapping(string => EvmErc20) registeredTokens;

    //By the token account id on near and user address on aurora return the user balance of this token in this contract
    //[token_address_on_near][user_address_on_aurora] => user_token_balance_in_aurora_fast_bridge
    mapping(string => mapping(address => uint128)) balance;

    event Unlock(
        uint128 nonce,
        address sender,
        string transferToken,
        uint128 transferAmount,
        string feeToken,
        uint128 feeAmount
    );
    event SetWhitelistedUsers(address[] users, bool[] states);
    event TokenRegistered(address auroraAddress, string nearAddress);
    event Withdraw(address recipient, string token, uint128 amount);
    event WithdrawFromNear(string token, uint128 amount);
    event InitTokenTransfer(
        address sender,
        string initTransferArg,
        string token,
        uint128 transferAmount,
        uint128 feeAmount,
        address recipient,
        bool isSuccessful
    );

    struct TransferMessage {
        uint64 validTill;
        string transferTokenAddressOnNear;
        address transferTokenAddressOnEth;
        uint128 transferTokenAmount;
        string feeTokenAddressOnNear;
        uint128 feeTokenAmount;
        address recipient;
        uint64 validTillBlockHeight;
        address auroraSender;
    }

    constructor(address wnearAddress, string memory bridgeAddress) {
        near = AuroraSdk.initNear(IERC20_NEAR(wnearAddress));
        bridgeAddressOnNear = bridgeAddress;

        _grantRole(CALLBACK_ROLE, AuroraSdk.nearRepresentitiveImplicitAddress(address(this)));
        _grantRole(ADMIN, msg.sender);

        whitelistedUsers[msg.sender] = true;
    }

    function setWhitelistedUsers(address[] memory users, bool[] memory states) public onlyRole(ADMIN) {
        require(users.length == states.length, "Arrays must be equal");

        for (uint256 i = 0; i < users.length; i++) {
            whitelistedUsers[users[i]] = states[i];
        }

        emit SetWhitelistedUsers(users, states);
    }


    function tokensRegistration(
        address auroraTokenAddress,
        string memory nearTokenAddress
    ) public onlyRole(ADMIN) {
        uint128 deposit = 12_500_000_000_000_000_000_000;
        near.wNEAR.transferFrom(msg.sender, address(this), uint256(deposit));
        bytes memory args = bytes(
            string.concat('{"account_id": "', getNearAddress(), '", "registration_only": true }')
        );

        PromiseCreateArgs memory callStorageDeposit = near.call(
            nearTokenAddress,
            "storage_deposit",
            args,
            deposit,
            BASE_NEAR_GAS
        );
        callStorageDeposit.transact();

        registeredTokens[nearTokenAddress] = EvmErc20(auroraTokenAddress);
        emit TokenRegistered(auroraTokenAddress, nearTokenAddress);
    }

    function initTokenTransfer(bytes memory initTransferArgs) public {
        require(whitelistedUsers[address(msg.sender)], "Sender not whitelisted!");
        TransferMessage memory transferMessage = decodeTransferMessageFromBorsh(initTransferArgs);
        require(
            transferMessage.auroraSender == msg.sender,
            "Aurora sender in transfer message doesn't equal to signer"
        );
        require(
            keccak256(abi.encodePacked(transferMessage.transferTokenAddressOnNear)) ==
                keccak256(abi.encodePacked(transferMessage.feeTokenAddressOnNear))
        );

        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));

        uint256 totalTokenAmount = uint256(
            transferMessage.transferTokenAmount + transferMessage.feeTokenAmount
        );

        EvmErc20 token = registeredTokens[transferMessage.transferTokenAddressOnNear];
        require(address(token) != address(0), "The token is not registered!");

        token.transferFrom(msg.sender, address(this), totalTokenAmount);
        token.withdrawToNear(bytes(getNearAddress()), totalTokenAmount);

        string memory initArgsBase64 = Base64.encode(initTransferArgs);
        bytes memory args = bytes(
            string.concat(
                '{"receiver_id": "',
                bridgeAddressOnNear,
                '", "amount": "',
                Strings.toString(totalTokenAmount),
                '", "msg": "',
                initArgsBase64,
                '"}'
            )
        );

        PromiseCreateArgs memory callFtTransfer = near.call(
            transferMessage.transferTokenAddressOnNear,
            "ft_transfer_call",
            args,
            1,
            INIT_TRANSFER_NEAR_GAS
        );
        bytes memory callbackArg = abi.encodeWithSelector(
            this.initTokenTransferCallback.selector,
            msg.sender,
            initTransferArgs
        );
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, 0, BASE_NEAR_GAS);

        callFtTransfer.then(callback).transact();
    }

    function initTokenTransferCallback(
        address signer,
        bytes memory initTransferArgs
    ) public onlyRole(CALLBACK_ROLE) {
        uint128 transferredAmount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferredAmount = stringToUint(AuroraSdk.promiseResult(0).output);
        }

        TransferMessage memory transferMessage = decodeTransferMessageFromBorsh(initTransferArgs);

        balance[transferMessage.transferTokenAddressOnNear][signer] += (transferMessage.transferTokenAmount +
            transferMessage.feeTokenAmount - transferredAmount);

        string memory initArgsBase64 = Base64.encode(initTransferArgs);
        bool isSuccessful = (transferredAmount != 0);
        emit InitTokenTransfer(signer,
            initArgsBase64,
            transferMessage.transferTokenAddressOnNear,
            transferMessage.transferTokenAmount,
            transferMessage.feeTokenAmount,
            transferMessage.recipient,
            isSuccessful
        );
    }

    function unlock(uint128 nonce, string memory proof) public {
        bytes memory args = bytes(
            string.concat(
                '{"nonce": "',
                Strings.toString(nonce),
                '", "proof": "',
                proof,
                '"}'
            )
        );

        PromiseCreateArgs memory callUnlock = near.call(bridgeAddressOnNear, "unlock", args, 0, UNLOCK_NEAR_GAS);
        bytes memory callbackArg = abi.encodeWithSelector(this.unlockCallback.selector, msg.sender, nonce);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, 0, BASE_NEAR_GAS);

        callUnlock.then(callback).transact();
    }

    function unlockCallback(address signer, uint128 nonce) public onlyRole(CALLBACK_ROLE) {
        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            TransferMessage memory transferMessage = decodeTransferMessageFromBorsh(
                AuroraSdk.promiseResult(0).output
            );

            balance[transferMessage.transferTokenAddressOnNear][signer] += transferMessage.transferTokenAmount;
            balance[transferMessage.feeTokenAddressOnNear][signer] += transferMessage.feeTokenAmount;

            emit Unlock(
                nonce,
                signer,
                transferMessage.transferTokenAddressOnNear,
                transferMessage.transferTokenAmount,
                transferMessage.feeTokenAddressOnNear,
                transferMessage.feeTokenAmount
            );
        }
    }

    function withdrawFromNear(string memory tokenId, uint128 amount) public {
        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));

        bytes memory args = bytes(
            string.concat('{"token_id": "', tokenId, '", "amount": "', Strings.toString(amount), '"}')
        );
        PromiseCreateArgs memory callWithdraw = near.call(bridgeAddressOnNear, "withdraw", args, 1, WITHDRAW_NEAR_GAS);
        bytes memory callbackArg = abi.encodeWithSelector(this.withdrawFromNearCallback.selector, tokenId, amount);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, 0, BASE_NEAR_GAS);

        callWithdraw.then(callback).transact();
    }

    function withdrawFromNearCallback(string memory tokenId, uint128 amount) public onlyRole(CALLBACK_ROLE) {
        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            emit WithdrawFromNear(tokenId, amount);
        }
    }

    function withdraw(string memory token) public {
        uint128 signerBalance = balance[token][msg.sender];

        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));
        bytes memory args = bytes(
            string.concat(
                '{"receiver_id": "aurora", "amount": "',
                Strings.toString(signerBalance),
                '", "msg": "',
                addressToString(msg.sender),
                '"}'
            )
        );
        PromiseCreateArgs memory callWithdraw = near.call(token, "ft_transfer_call", args, 1, WITHDRAW_NEAR_GAS);
        bytes memory callbackArg = abi.encodeWithSelector(this.withdrawCallback.selector, msg.sender, token);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, 0, BASE_NEAR_GAS);

        callWithdraw.then(callback).transact();
    }

    function withdrawCallback(address signer, string memory token) public onlyRole(CALLBACK_ROLE) {
        uint128 transferredAmount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferredAmount = stringToUint(AuroraSdk.promiseResult(0).output);
        }

        if (transferredAmount > 0) {
            balance[token][signer] -= transferredAmount;
            emit Withdraw(signer, token, transferredAmount);
        }
    }

    function decodeTransferMessageFromBorsh(
        bytes memory transferMessageBorsh
    ) private pure returns (TransferMessage memory) {
        TransferMessage memory result;
        Borsh.Data memory borsh = Borsh.from(transferMessageBorsh);
        result.validTill = borsh.decodeU64();
        result.transferTokenAddressOnNear = string(borsh.decodeBytes()); //transfer token address on Near
        result.transferTokenAddressOnEth = address(borsh.decodeBytes20()); //transfer token address on Ethereum
        result.transferTokenAmount = borsh.decodeU128();
        result.feeTokenAddressOnNear = string(borsh.decodeBytes()); // fee token address on Near
        result.feeTokenAmount = borsh.decodeU128();
        result.recipient = address(borsh.decodeBytes20()); //recipient
        uint8 optionValidTill = borsh.decodeU8();
        if (optionValidTill == 1) {
            result.validTillBlockHeight = borsh.decodeU64(); //valid_till_block_height
        }
        uint8 optionAuroraSender = borsh.decodeU8();
        if (optionAuroraSender == 1) {
            result.auroraSender = address(borsh.decodeBytes20());
        }
        return result;
    }

    function getNearAddress() public view returns (string memory) {
        string memory auroraAddress = addressToString(address(this));
        return string.concat(auroraAddress, ".aurora");
    }

    function getTokenAuroraAddress(string memory nearTokenAddress) public view returns (address) {
        return address(registeredTokens[nearTokenAddress]);
    }

    function getUserBalance(string memory nearTokenAddress, address userAddress) public view returns (uint128) {
        return balance[nearTokenAddress][userAddress];
    }

    function addressToString(address auroraAddress) private pure returns (string memory) {
        return Utils.bytesToHex(abi.encodePacked(auroraAddress));
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
}
