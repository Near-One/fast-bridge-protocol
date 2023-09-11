// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {IERC20 as IERC20_NEAR} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AuroraSdk, NEAR, PromiseCreateArgs, PromiseResultStatus, PromiseWithCallback} from "@auroraisnear/aurora-sdk/aurora-sdk/AuroraSdk.sol";
import "@auroraisnear/aurora-sdk/aurora-sdk/Borsh.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "./IEvmErc20.sol";
import "./UtilsFastBridge.sol";

struct TokenInfo {
    IEvmErc20 auroraTokenAddress;
    bool isStorageRegistered;
}

contract AuroraErc20FastBridge is Initializable, UUPSUpgradeable, AccessControlUpgradeable, PausableUpgradeable {
    using AuroraSdk for NEAR;
    using AuroraSdk for PromiseCreateArgs;
    using AuroraSdk for PromiseWithCallback;
    using Borsh for Borsh.Data;

    bytes32 public constant PAUSABLE_ADMIN_ROLE = keccak256("PAUSABLE_ADMIN_ROLE");
    bytes32 public constant UNPAUSABLE_ADMIN_ROLE = keccak256("UNPAUSABLE_ADMIN_ROLE");
    bytes32 public constant CALLBACK_ROLE = keccak256("CALLBACK_ROLE");
    bytes32 public constant WHITELIST_MANAGER = keccak256("WHITELIST_MANAGER");

    uint64 constant BASE_NEAR_GAS = 10_000_000_000_000;
    uint64 constant WITHDRAW_NEAR_GAS = 50_000_000_000_000;
    uint64 constant INIT_TRANSFER_NEAR_GAS = 100_000_000_000_000;
    uint64 constant INIT_TRANSFER_CALLBACK_NEAR_GAS = 20_000_000_000_000;
    uint64 constant UNLOCK_NEAR_GAS = 150_000_000_000_000;

    uint128 constant NEAR_STORAGE_DEPOSIT = 12_500_000_000_000_000_000_000;

    uint128 constant ONE_YOCTO = 1;
    uint128 constant NO_DEPOSIT = 0;

    NEAR public near;
    string public fastBridgeAccountIdOnNear;
    string public auroraEngineAccountIdOnNear;
    bool public isWhitelistModeEnabled;

    //The Whitelisted Aurora users which allowed use fast bridge.
    mapping(address => bool) whitelistedUsers;

    //By the token account id on near returns correspondent ERC20 Aurora token.
    //token_near_account_id => aurora_erc20_token
    mapping(string => TokenInfo) registeredTokens;

    //By the token account id on near and user address on aurora return the user balance of this token in this contract
    //[token_near_account_id][user_address_on_aurora] => user_token_balance_in_aurora_fast_bridge
    mapping(string => mapping(address => uint128)) balance;

    event Unlock(
        uint128 nonce,
        address sender,
        string transferToken,
        uint128 transferAmount,
        string feeToken,
        uint128 feeAmount
    );
    event SetWhitelistModeForUsers(address[] users, bool[] states);
    event SetWhitelistMode(bool);
    event TokenRegistered(address tokenAuroraAddress, string tokenNearAccountId);
    event WithdrawFromImplicitNearAccount(address recipient, string token, uint128 amount);
    event FastBridgeWithdrawOnNear(string token, uint128 amount);
    event InitTokenTransfer(
        address sender,
        string initTransferArg,
        string token,
        uint128 transferAmount,
        uint128 feeAmount,
        address recipient,
        bool isSuccessful
    );
    event TokenStorageDeposit(string tokenNearAccountId, address tokenAuroraAddress, string registeredAccountId);

    struct TransferMessage {
        uint64 validTill;
        string transferTokenAccountIdOnNear;
        address transferTokenAddressOnEth;
        uint128 transferTokenAmount;
        string feeTokenAccountIdOnNear;
        uint128 feeTokenAmount;
        address recipient;
        uint64 validTillBlockHeight;
        address auroraSender;
    }

    /**
      * @dev Initializes the Aurora Fast Bridge contract with essential parameters and access control roles.
      * @param wnearAddress The address of the Wrapped NEAR (wNEAR) token contract.
      * @param fastBridgeAccountId The Fast Bridge account ID ofon the NEAR blockchain.
      * @param auroraEngineAccountId The Aurora Engine account ID on the NEAR blockchain.
      * @param _isWhitelistModeEnabled A boolean indicating whether whitelist mode is initially enabled.
      * Effects:
      * - Initializes the contract with access control roles and configuration parameters.
      * - Grants necessary roles to the contract owner and sets whitelist mode status.
    */
    function initialize(
        address wnearAddress,
        string calldata fastBridgeAccountId,
        string calldata auroraEngineAccountId,
        bool _isWhitelistModeEnabled
    ) external initializer {
        __Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();
        near = AuroraSdk.initNear(IERC20_NEAR(wnearAddress));
        fastBridgeAccountIdOnNear = fastBridgeAccountId;
        auroraEngineAccountIdOnNear = auroraEngineAccountId;

        _grantRole(CALLBACK_ROLE, AuroraSdk.nearRepresentitiveImplicitAddress(address(this)));
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(WHITELIST_MANAGER, msg.sender);
        _setupRole(PAUSABLE_ADMIN_ROLE, _msgSender());
        _setupRole(UNPAUSABLE_ADMIN_ROLE, _msgSender());

        whitelistedUsers[msg.sender] = true;
        isWhitelistModeEnabled = _isWhitelistModeEnabled;
    }

    /**
     * @dev Sets the Whitelist Mode for the contract.
     * @param isEnabled A boolean indicating whether to enable (true) or disable (false) Whitelist Mode.
     * Requirements:
     * - Caller must have the 'WHITELIST_MANAGER' role to execute this function.
     * Effects:
     * - Updates the contract's Whitelist Mode to the specified value.
     * - Emits a 'SetWhitelistMode' event to signal the change in Whitelist Mode status.
    */
    function setWhitelistMode(bool isEnabled) external onlyRole(WHITELIST_MANAGER) {
        isWhitelistModeEnabled = isEnabled;

        emit SetWhitelistMode(isEnabled);
    }

    /**
     * @dev Checks if a user is whitelisted based on the contract's Whitelist Mode.
     * @param user The address of the user to check for whitelist status.
     * @return A boolean indicating whether the user is whitelisted (true) or not (false).
    */
    function isUserWhitelisted(address user) public view returns (bool) {
        if (isWhitelistModeEnabled == false) {
            return true;
        } else {
            return whitelistedUsers[user];
        }
    }

    /**
     * @dev Sets the Whitelist Mode for multiple users in bulk.
     * @param users An array of user addresses to set the Whitelist Mode for.
     * @param states An array of booleans indicating the Whitelist Mode status for each user.
     * Requirements:
     * - Caller must have the 'WHITELIST_MANAGER' role to execute this function.
     * - The 'users' and 'states' arrays must have the same length.
     * Effects:
     * - Updates the Whitelist Mode status for the specified users.
     * - Emits a 'SetWhitelistModeForUsers' event to signal the changes in Whitelist Mode for the users.
    */
    function setWhitelistModeForUsers(
        address[] calldata users,
        bool[] calldata states
    ) external onlyRole(WHITELIST_MANAGER) {
        require(users.length == states.length, "Arrays must be equal");

        for (uint256 i = 0; i < users.length; i++) {
            whitelistedUsers[users[i]] = states[i];
        }

        emit SetWhitelistModeForUsers(users, states);
    }

    /**
      * @dev Registers a binding of "nearTokenAccountId:auroraTokenAddress" in "AuroraFastBridge" contract.
      * @param nearTokenAccountId The NEAR token account ID associated with the Aurora token.
      * Requirements:
      * - Caller must have the 'DEFAULT_ADMIN_ROLE' role to execute this function.
      * Effects:
      * - Call the get_erc20_from_nep141 function for extract the Aurora token address
    */
    function registerToken(
        string calldata nearTokenAccountId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        PromiseCreateArgs memory callGetErc20FromNep141 = near.call(
            auroraEngineAccountIdOnNear,
            "get_erc20_from_nep141",
            UtilsFastBridge.borshEncode(bytes(nearTokenAccountId)),
            NO_DEPOSIT,
            BASE_NEAR_GAS
        );

        PromiseCreateArgs memory callback = near.auroraCall(
            address(this),
            abi.encodeWithSelector(this.getErc20FromNep141Callback.selector, nearTokenAccountId),
            NO_DEPOSIT,
            BASE_NEAR_GAS
        );

        callGetErc20FromNep141.then(callback).transact();
    }

    /**
      * @dev The callback for a `registerToken` method.
      * @param nearTokenAccountId The NEAR token account ID associated with the Aurora token.
      * Requirements:
      * - Caller must have the 'CALLBACK_ROLE' to execute this function.
      * Effects:
      * - Registers the Aurora token with the NEAR token account.
      * - Emits a 'TokenRegistered' event to signal the successful registration.
    */
    function getErc20FromNep141Callback(string calldata nearTokenAccountId) external onlyRole(CALLBACK_ROLE) {
        require(
            AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful,
            "ERROR: The `get_erc20_from_nep141()` XCC call failed"
        );

        address auroraTokenAddress = address(uint160(bytes20(AuroraSdk.promiseResult(0).output)));

        registeredTokens[nearTokenAccountId] = TokenInfo(IEvmErc20(auroraTokenAddress), false);
        emit TokenRegistered(auroraTokenAddress, nearTokenAccountId);
    }

    /**
      * @dev Puts a storage deposit in "nearTokenAccountId" for the "AuroraFastBridge" implicit NEAR Account ID.
      * @param nearTokenAccountId The NEAR token account ID associated with the Aurora token.
      * @param storageDepositAmount The amount of wNear for storage deposit
      * Requirements:
      * - Caller must have the 'DEFAULT_ADMIN_ROLE' role to execute this function.
      * Effects:
      * - Calls the NEAR blockchain to perform a storage deposit for the specified NEAR token account.
    */
    function storageDeposit(string calldata nearTokenAccountId, uint128 storageDepositAmount) external {
        TokenInfo storage tokenInfo = registeredTokens[nearTokenAccountId];
        require(tokenInfo.isStorageRegistered == false, "The token's storage is already registered");
        require(address(tokenInfo.auroraTokenAddress) != address(0), "The token is not registered");

        bytes memory args = bytes(
            string.concat('{"account_id": "', getImplicitNearAccountIdForSelf(), '", "registration_only": true }')
        );

        PromiseCreateArgs memory callStorageDeposit = near.call(
            nearTokenAccountId,
            "storage_deposit",
            args,
            storageDepositAmount,
            BASE_NEAR_GAS
        );

        PromiseCreateArgs memory callback = near.auroraCall(
            address(this),
            abi.encodeWithSelector(this.storageDepositCallback.selector, nearTokenAccountId),
            NO_DEPOSIT,
            BASE_NEAR_GAS
        );

        callStorageDeposit.then(callback).transact();
    }

    /**
      * @dev The callback for a `storageDeposit` method.
      * @param nearTokenAccountId The NEAR token account ID associated with the Aurora token.
      * Requirements:
      * - Caller must have the 'CALLBACK_ROLE' to execute this function.
      * Effects:
      * - Save the `isStorageRegistered` flag for token.
      * - Emits a 'TokenStorageDeposit' event to signal the successful storageDeposit.
    */
    function storageDepositCallback(string calldata nearTokenAccountId) external onlyRole(CALLBACK_ROLE) {
        require(
            AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful,
            "ERROR: The `storage_deposit()` XCC call failed"
        );

        registeredTokens[nearTokenAccountId].isStorageRegistered = true;

        emit TokenStorageDeposit(nearTokenAccountId,
            address(registeredTokens[nearTokenAccountId].auroraTokenAddress),
            getImplicitNearAccountIdForSelf());
    }

    /**
      * @dev Initiates a token transfer from the Aurora to the Ethereum blockchain.
      * @param initTransferArgs The encoded transfer message arguments.
      * Requirements:
      * - The contract must not be paused to execute this function.
      * - The contract must have a sufficient wNEAR balance for processing.
      * - The sender initiating the transfer must be whitelisted or Whitelist Mode should be disabled.
      * - The Aurora sender address in the transfer message must match the function caller.
      * - The transfer and fee tokens in the transfer message must be the same.
      * - The transfer token must be registered with the contract.
      * - The contract must be allowed to spend the sender's tokens.
      * Effects:
      * - Initiates a token transfer from the sender on Aurora to the Ethereum.
    */
    function initTokenTransfer(bytes calldata initTransferArgs) external whenNotPaused {
        require(near.wNEAR.balanceOf(address(this)) >= ONE_YOCTO, "Not enough wNEAR balance");
        require(isUserWhitelisted(address(msg.sender)), "Sender not whitelisted!");
        TransferMessage memory transferMessage = _decodeTransferMessageFromBorsh(initTransferArgs);
        require(
            transferMessage.auroraSender == msg.sender,
            "Aurora sender address in the transfer message doesn't match the signer"
        );

        require(
            UtilsFastBridge.isStrEqual(transferMessage.transferTokenAccountIdOnNear, transferMessage.feeTokenAccountIdOnNear),
            "The transfer and fee tokens should be the same"
        );

        TokenInfo memory tokenInfo = registeredTokens[transferMessage.transferTokenAccountIdOnNear];
        IEvmErc20 token = tokenInfo.auroraTokenAddress;
        require(tokenInfo.isStorageRegistered == true, "The token storage is not registered");

        require(address(token) != address(0), "The token is not registered");

        uint256 totalTokenAmount = uint256(transferMessage.transferTokenAmount + transferMessage.feeTokenAmount);

        token.transferFrom(msg.sender, address(this), totalTokenAmount);

        // WARNING: The `withdrawToNear` method works asynchronously.
        // As a result, there is no guarantee that this method will be completed before `initTransfer()`.
        // In case of such an error, the user will be able to call the `withdraw()` method and get his tokens back.
        // We expect such an error not to happen as long as transactions are executed in one shard.
        token.withdrawToNear(bytes(getImplicitNearAccountIdForSelf()), totalTokenAmount);

        string memory initArgsBase64 = Base64.encode(initTransferArgs);
        bytes memory args = bytes(
            string.concat(
                '{"receiver_id": "',
                fastBridgeAccountIdOnNear,
                '", "amount": "',
                Strings.toString(totalTokenAmount),
                '", "msg": "',
                initArgsBase64,
                '"}'
            )
        );

        PromiseCreateArgs memory callFtTransfer = UtilsFastBridge.callWithoutTransferWNear(
            near,
            transferMessage.transferTokenAccountIdOnNear,
            "ft_transfer_call",
            args,
            ONE_YOCTO,
            INIT_TRANSFER_NEAR_GAS
        );
        bytes memory callbackArg = abi.encodeWithSelector(
            this.initTokenTransferCallback.selector,
            msg.sender,
            initTransferArgs
        );
        PromiseCreateArgs memory callback = near.auroraCall(
            address(this),
            callbackArg,
            NO_DEPOSIT,
            INIT_TRANSFER_CALLBACK_NEAR_GAS
        );

        callFtTransfer.then(callback).transact();
    }

    /**
      * @dev The callback for a initTokenTransfer method.
      * @param signer The address of the signer who initiated the token transfer.
      * @param initTransferArgs The encoded transfer message arguments.
      * Requirements:
      * - Caller must have the 'CALLBACK_ROLE' to execute this function.
      * Effects:
      * - Calculates and refunds any remaining tokens to the signer if the transfer was partial.
      * - Emits an 'InitTokenTransfer' event to signal the completion of the token transfer initialization.
    */
    function initTokenTransferCallback(
        address signer,
        bytes calldata initTransferArgs
    ) external onlyRole(CALLBACK_ROLE) {
        uint128 transferredAmount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferredAmount = UtilsFastBridge.stringToUint(AuroraSdk.promiseResult(0).output);
        }

        TransferMessage memory transferMessage = _decodeTransferMessageFromBorsh(initTransferArgs);

        uint128 refundAmount = (transferMessage.transferTokenAmount +
            transferMessage.feeTokenAmount -
            transferredAmount);
        if (refundAmount > 0) {
            balance[transferMessage.transferTokenAccountIdOnNear][signer] += refundAmount;
        }

        string memory initArgsBase64 = Base64.encode(initTransferArgs);
        emit InitTokenTransfer(
            signer,
            initArgsBase64,
            transferMessage.transferTokenAccountIdOnNear,
            transferMessage.transferTokenAmount,
            transferMessage.feeTokenAmount,
            transferMessage.recipient,
            (transferredAmount != 0)
        );
    }

    /**
      * @dev Initiates the unlocking of tokens on the Fast Bridge on Near blockchain.
      * @param nonce The nonce of the fast bridge token transfer on Near.
      * @param proof A Base64-encoded proof of the non-existence of the transfer on Ethereum after the `valid_till` timestamp is passed.
      * Requirements:
      * - The method must be called by token transfer initiator
      * - The contract must not be paused to execute this function.
      * Effects:
      * - Initiates the unlocking process by making a call to the Fast Bridge contract on Near blockchain.
    */
    function unlock(uint128 nonce, string calldata proof) external whenNotPaused {
        bytes memory args = bytes(string.concat('{"nonce": "', Strings.toString(nonce), '", "proof": "', proof, '"}'));

        PromiseCreateArgs memory callUnlock = near.call(
            fastBridgeAccountIdOnNear,
            "unlock",
            args,
            NO_DEPOSIT,
            UNLOCK_NEAR_GAS
        );
        bytes memory callbackArg = abi.encodeWithSelector(this.unlockCallback.selector, nonce);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, NO_DEPOSIT, BASE_NEAR_GAS);

        callUnlock.then(callback).transact();
    }

    /**
      * @dev The callback for a unlock method.
      * @param nonce The nonce of the fast bridge token transfer on Near.
      * Requirements:
      * - Caller must have the 'CALLBACK_ROLE' to execute this function.
      * Effects:
      * - Checks if the 'Unlock' cross-contract call (XCC) on Aurora was successful.
      * - Decodes the output of the XCC into a TransferMessage structure.
      * - Updates the balances of the Aurora sender for the transferred and fee tokens.
      * - Emits an 'Unlock' event to signal the completion of the token unlocking.
    */
    function unlockCallback(uint128 nonce) external onlyRole(CALLBACK_ROLE) {
        require(AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful, "ERROR: The `Unlock` XCC failed");

        TransferMessage memory transferMessage = _decodeTransferMessageFromBorsh(AuroraSdk.promiseResult(0).output);

        balance[transferMessage.transferTokenAccountIdOnNear][transferMessage.auroraSender] += transferMessage
            .transferTokenAmount;

        balance[transferMessage.feeTokenAccountIdOnNear][transferMessage.auroraSender] += transferMessage
            .feeTokenAmount;

        emit Unlock(
            nonce,
            transferMessage.auroraSender,
            transferMessage.transferTokenAccountIdOnNear,
            transferMessage.transferTokenAmount,
            transferMessage.feeTokenAccountIdOnNear,
            transferMessage.feeTokenAmount
        );
    }

    /**
      * @dev Initiates a fast bridge withdrawal of tokens on the NEAR blockchain.
      * @param tokenId The Account Id of the token to be withdrawn.
      * @param amount The amount of tokens to withdraw.
      * Requirements:
      * - The contract must not be paused to execute this function.
      * - The contract must have a sufficient wNEAR balance for processing.
      * Effects:
      * - Initiates the fast bridge withdrawal process by making a cross-contract call to the NEAR blockchain.
    */
    function fastBridgeWithdrawOnNear(string calldata tokenId, uint128 amount) external whenNotPaused {
        require(near.wNEAR.balanceOf(address(this)) >= ONE_YOCTO, "Not enough wNEAR balance");
        bytes memory args = bytes(
            string.concat('{"token_id": "', tokenId, '", "amount": "', Strings.toString(amount), '"}')
        );

        PromiseCreateArgs memory callWithdraw = UtilsFastBridge.callWithoutTransferWNear(
            near,
            fastBridgeAccountIdOnNear,
            "withdraw",
            args,
            ONE_YOCTO,
            WITHDRAW_NEAR_GAS
        );

        bytes memory callbackArg = abi.encodeWithSelector(
            this.fastBridgeWithdrawOnNearCallback.selector,
            tokenId,
            amount
        );
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, NO_DEPOSIT, BASE_NEAR_GAS);

        callWithdraw.then(callback).transact();
    }

    /**
      * @dev The callback for a fastBridgeWithdrawOnNear method.
      * @param tokenId The Account Is of the token that was withdrawn on NEAR Fast Bridge to implicit account.
      * @param amount The amount of tokens that were withdrawn.
      * Requirements:
      * - Caller must have the 'CALLBACK_ROLE' to execute this function.
      * Effects:
      * - Checks if the 'Withdraw' cross-contract call (XCC) was successful.
      * - Emits a 'FastBridgeWithdrawOnNear' event to signal the completion of the withdrawal.
    */
    function fastBridgeWithdrawOnNearCallback(
        string calldata tokenId,
        uint128 amount
    ) external onlyRole(CALLBACK_ROLE) {
        require(
            AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful,
            "ERROR: The `Withdraw` XCC is fail"
        );

        emit FastBridgeWithdrawOnNear(tokenId, amount);
    }

    /**
      * @dev Initiates the withdrawal of tokens from the implicit NEAR account of this fast bridge contract to the signer on the Aurora blockchain.
      * @param token The token NEAR account id to be withdrawn.
      * Requirements:
      * - The contract must not be paused to execute this function.
      * - The contract must have a sufficient wNEAR balance for processing.
      * - The caller must have a positive token balance for the specified token.
      * Effects:
      * - Initiates the withdrawal process by making a call to the NEAR blockchain.
      * - Deducts the withdrawn amount from the caller's token balance.
    */
    function withdrawFromImplicitNearAccount(string calldata token) external whenNotPaused {
        require(near.wNEAR.balanceOf(address(this)) >= ONE_YOCTO, "Not enough wNEAR balance");
        uint128 signerBalance = balance[token][msg.sender];
        require(signerBalance > 0, "The signer token balance = 0");

        bytes memory args = bytes(
            string.concat(
                '{"receiver_id": "',
                auroraEngineAccountIdOnNear,
                '", "amount": "',
                Strings.toString(signerBalance),
                '", "msg": "',
                UtilsFastBridge.addressToString(msg.sender),
                '"}'
            )
        );
        balance[token][msg.sender] -= signerBalance;

        PromiseCreateArgs memory callWithdraw = UtilsFastBridge.callWithoutTransferWNear(
            near,
            token,
            "ft_transfer_call",
            args,
            ONE_YOCTO,
            WITHDRAW_NEAR_GAS
        );

        bytes memory callbackArg = abi.encodeWithSelector(
            this.withdrawFromImplicitNearAccountCallback.selector,
            msg.sender,
            token,
            signerBalance
        );
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, NO_DEPOSIT, BASE_NEAR_GAS);

        callWithdraw.then(callback).transact();
    }

    /**
      * @dev The callback for withdrawFromImplicitNearAccount method.
      * @param signer The address of the signer who initiated the withdrawal.
      * @param token The token account Id that was withdrawn.
      * @param amount The amount of tokens that were requested to be withdrawn.
      * Requirements:
      * - Caller must have the 'CALLBACK_ROLE' to execute this function.
      * Effects:
      * - Checks if the token withdrawal on the Aurora blockchain was successful.
      * - Calculates the transferred and refund amounts based on the callback result.
      * - Emits a 'WithdrawFromImplicitNearAccount' event to signal the completion of the withdrawal.
    */
    function withdrawFromImplicitNearAccountCallback(
        address signer,
        string calldata token,
        uint128 amount
    ) external onlyRole(CALLBACK_ROLE) {
        uint128 transferredAmount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferredAmount = UtilsFastBridge.stringToUint(AuroraSdk.promiseResult(0).output);
        }

        uint128 refundAmount = amount - transferredAmount;

        if (refundAmount > 0) {
            balance[token][signer] += refundAmount;
        }

        if (transferredAmount > 0) {
            emit WithdrawFromImplicitNearAccount(signer, token, transferredAmount);
        }
    }

    function _decodeTransferMessageFromBorsh(
        bytes memory transferMessageBorsh
    ) private pure returns (TransferMessage memory) {
        TransferMessage memory result;
        Borsh.Data memory borsh = Borsh.from(transferMessageBorsh);
        result.validTill = borsh.decodeU64();
        result.transferTokenAccountIdOnNear = string(borsh.decodeBytes());
        result.transferTokenAddressOnEth = address(borsh.decodeBytes20());
        result.transferTokenAmount = borsh.decodeU128();
        result.feeTokenAccountIdOnNear = string(borsh.decodeBytes());
        result.feeTokenAmount = borsh.decodeU128();
        result.recipient = address(borsh.decodeBytes20());
        uint8 optionValidTill = borsh.decodeU8();
        if (optionValidTill == 1) {
            result.validTillBlockHeight = borsh.decodeU64();
        }
        uint8 optionAuroraSender = borsh.decodeU8();
        if (optionAuroraSender == 1) {
            result.auroraSender = address(borsh.decodeBytes20());
        }
        return result;
    }

    /**
      * @dev Get the implicit NEAR account ID associated with this contract's address and the Aurora Engine account on NEAR.
      * @return The implicit NEAR account ID of this Aurora Fast Bridge contract as a concatenated string.
    */
    function getImplicitNearAccountIdForSelf() public view returns (string memory) {
        return string.concat(UtilsFastBridge.addressToString(address(this)), ".", auroraEngineAccountIdOnNear);
    }

    /**
     * @dev Retrieves the Aurora EVM token address associated with a given NEAR token account ID.
     * @param nearTokenAccountId The NEAR token account ID for which to retrieve the corresponding Aurora EVM token address.
     * @return The Aurora EVM token address corresponding to the provided NEAR token account ID.
    */
    function getTokenAuroraAddress(string calldata nearTokenAccountId) external view returns (address) {
        return address(registeredTokens[nearTokenAccountId].auroraTokenAddress);
    }

    /**
     * @dev Retrieves the token balance of a user for a specific NEAR token account ID.
     * @param nearTokenAccountId The NEAR token account ID for which to retrieve the user's balance.
     * @param userAddress The address of the user for whom to retrieve the balance.
     * @return The token balance of the specified user for the given NEAR token account ID.
    */
    function getUserBalance(string calldata nearTokenAccountId, address userAddress) external view returns (uint128) {
        return balance[nearTokenAccountId][userAddress];
    }

    function isStorageRegistered(string calldata nearTokenAccountId) public view returns (bool) {
        return registeredTokens[nearTokenAccountId].isStorageRegistered;
    }

    /// Pauses all the operations in Fast Bridge. It affects only user-accessible operations.
    function pause() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        _pause();
    }

    /// Unpauses all the operations in Fast Bridge. It affects only user-accessible operations.
    function unpause() external onlyRole(UNPAUSABLE_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @dev Internal function called by the proxy contract to authorize an upgrade to a new implementation address
     * using the UUPS proxy upgrade pattern. Overrides the default `_authorizeUpgrade` function from the `UUPSUpgradeable` contract.
     * This function does not need to perform any extra authorization checks other than restricting the execution of the function to the admin and reverting otherwise.
     * @param newImplementation Address of the new implementation contract.
     * Requirements:
     * - The caller must have the `DEFAULT_ADMIN_ROLE`.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
