// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {IERC20 as IERC20_NEAR} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AuroraSdk, NEAR, PromiseCreateArgs, PromiseResultStatus, PromiseWithCallback} from "@auroraisnear/aurora-sdk/aurora-sdk/AuroraSdk.sol";
import "@auroraisnear/aurora-sdk/aurora-sdk/Borsh.sol";
import "@auroraisnear/aurora-sdk/aurora-sdk/Utils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "./IEvmErc20.sol";

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
    uint64 constant UNLOCK_NEAR_GAS = 150_000_000_000_000;

    uint128 constant NEAR_STORAGE_DEPOSIT = 12_500_000_000_000_000_000_000;

    NEAR public near;
    string public bridgeAddressOnNear;
    string public auroraEngineAccountIdOnNear;
    bool public isWhitelistModeEnabled;

    //The Whitelisted Aurora users which allowed use fast bridge.
    mapping(address => bool) whitelistedUsers;

    //By the token address on near returns correspondent ERC20 Aurora token.
    //[token_address_on_near] => aurora_erc20_token
    mapping(string => IEvmErc20) registeredTokens;

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
    event SetWhitelistModeForUsers(address[] users, bool[] states);
    event SetWhitelistMode(bool);
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

    function initialize(
        address wnearAddress,
        string calldata bridgeAddress,
        string calldata auroraEngineAccountId,
        bool _isWhitelistModeEnabled
    ) external initializer {
        __Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();
        near = AuroraSdk.initNear(IERC20_NEAR(wnearAddress));
        bridgeAddressOnNear = bridgeAddress;
        auroraEngineAccountIdOnNear = auroraEngineAccountId;

        _grantRole(CALLBACK_ROLE, AuroraSdk.nearRepresentitiveImplicitAddress(address(this)));
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(WHITELIST_MANAGER, msg.sender);
        _setupRole(PAUSABLE_ADMIN_ROLE, _msgSender());
        _setupRole(UNPAUSABLE_ADMIN_ROLE, _msgSender());

        whitelistedUsers[msg.sender] = true;
        isWhitelistModeEnabled = _isWhitelistModeEnabled;
    }

    function setWhitelistMode(bool isEnabled) external onlyRole(WHITELIST_MANAGER) {
        isWhitelistModeEnabled = isEnabled;

        emit SetWhitelistMode(isEnabled);
    }

    function isUserWhitelisted(address user) public view returns (bool) {
        if (isWhitelistModeEnabled == false) {
            return true;
        } else {
            return whitelistedUsers[user];
        }
    }

    function setWhitelistModeForUsers(address[] calldata users, bool[] calldata states) external onlyRole(WHITELIST_MANAGER) {
        require(users.length == states.length, "Arrays must be equal");

        for (uint256 i = 0; i < users.length; i++) {
            whitelistedUsers[users[i]] = states[i];
        }

        emit SetWhitelistModeForUsers(users, states);
    }

    function registerToken(
        address auroraTokenAddress,
        string calldata nearTokenAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        near.wNEAR.transferFrom(msg.sender, address(this), uint256(NEAR_STORAGE_DEPOSIT));
        bytes memory args = bytes(
            string.concat('{"account_id": "', getNearAddress(), '", "registration_only": true }')
        );

        PromiseCreateArgs memory callStorageDeposit = near.call(
            nearTokenAddress,
            "storage_deposit",
            args,
            NEAR_STORAGE_DEPOSIT,
            BASE_NEAR_GAS
        );
        callStorageDeposit.transact();

        registeredTokens[nearTokenAddress] = IEvmErc20(auroraTokenAddress);
        emit TokenRegistered(auroraTokenAddress, nearTokenAddress);
    }

    function initTokenTransfer(bytes calldata initTransferArgs) external whenNotPaused {
        require(isUserWhitelisted(address(msg.sender)), "Sender not whitelisted!");
        TransferMessage memory transferMessage = _decodeTransferMessageFromBorsh(initTransferArgs);
        require(
            transferMessage.auroraSender == msg.sender,
            "Aurora sender in transfer message doesn't equal to signer"
        );

        require(
            _is_equal(transferMessage.transferTokenAddressOnNear, transferMessage.feeTokenAddressOnNear),
            "The transfer and fee tokens are different. Different tokens not supported yet."
        );

        IEvmErc20 token = registeredTokens[transferMessage.transferTokenAddressOnNear];
        require(address(token) != address(0), "The token is not registered!");
        require(near.wNEAR.balanceOf(address(this)) > 0, "Not enough wNEAR balance of AuroraErc20FastBridge");

        uint256 totalTokenAmount = uint256(transferMessage.transferTokenAmount + transferMessage.feeTokenAmount);

        token.transferFrom(msg.sender, address(this), totalTokenAmount);

        // WARNING: The `withdrawToNear` method works asynchronously.
        // As a result, there is no guarantee that this method will be completed before `initTransfer`.
        // In case of such an error, the user will be able to call `withdraw` method and get his/her tokens back.
        // We expect such an error not to happen as long as transactions were executed in one shard.
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

    function initTokenTransferCallback(address signer, bytes calldata initTransferArgs) external onlyRole(CALLBACK_ROLE) {
        uint128 transferredAmount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferredAmount = _stringToUint(AuroraSdk.promiseResult(0).output);
        }

        TransferMessage memory transferMessage = _decodeTransferMessageFromBorsh(initTransferArgs);

        balance[transferMessage.transferTokenAddressOnNear][signer] += (transferMessage.transferTokenAmount +
            transferMessage.feeTokenAmount -
            transferredAmount);

        string memory initArgsBase64 = Base64.encode(initTransferArgs);
        emit InitTokenTransfer(
            signer,
            initArgsBase64,
            transferMessage.transferTokenAddressOnNear,
            transferMessage.transferTokenAmount,
            transferMessage.feeTokenAmount,
            transferMessage.recipient,
            (transferredAmount != 0)
        );
    }

    function unlock(uint128 nonce, string calldata proof) external whenNotPaused {
        bytes memory args = bytes(string.concat('{"nonce": "', Strings.toString(nonce), '", "proof": "', proof, '"}'));

        PromiseCreateArgs memory callUnlock = near.call(bridgeAddressOnNear, "unlock", args, 0, UNLOCK_NEAR_GAS);
        bytes memory callbackArg = abi.encodeWithSelector(this.unlockCallback.selector, msg.sender, nonce);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, 0, BASE_NEAR_GAS);

        callUnlock.then(callback).transact();
    }

    function unlockCallback(address signer, uint128 nonce) external onlyRole(CALLBACK_ROLE) {
        require(AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful, "ERROR: The `Unlock` XCC is fail");

        TransferMessage memory transferMessage = _decodeTransferMessageFromBorsh(AuroraSdk.promiseResult(0).output);

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

    function withdrawFromNear(string calldata tokenId, uint128 amount) external whenNotPaused {
        require(near.wNEAR.balanceOf(address(this)) > 0, "Not enough wNEAR balance of AuroraErc20FastBridge");

        bytes memory args = bytes(
            string.concat('{"token_id": "', tokenId, '", "amount": "', Strings.toString(amount), '"}')
        );
        PromiseCreateArgs memory callWithdraw = near.call(bridgeAddressOnNear, "withdraw", args, 1, WITHDRAW_NEAR_GAS);
        bytes memory callbackArg = abi.encodeWithSelector(this.withdrawFromNearCallback.selector, tokenId, amount);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, 0, BASE_NEAR_GAS);

        callWithdraw.then(callback).transact();
    }

    function withdrawFromNearCallback(string calldata tokenId, uint128 amount) external onlyRole(CALLBACK_ROLE) {
        require(
            AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful,
            "ERROR: The `Withdraw From Near` XCC is fail"
        );

        emit WithdrawFromNear(tokenId, amount);
    }

    function withdraw(string calldata token) external whenNotPaused {
        uint128 signerBalance = balance[token][msg.sender];

        require(signerBalance > 0, "The signer token balance = 0");
        require(near.wNEAR.balanceOf(address(this)) > 0, "Not enough wNEAR balance of AuroraErc20FastBridge");

        bytes memory args = bytes(
            string.concat(
                '{"receiver_id": "',
                auroraEngineAccountIdOnNear,
                '", "amount": "',
                Strings.toString(signerBalance),
                '", "msg": "',
                _addressToString(msg.sender),
                '"}'
            )
        );
        balance[token][msg.sender] -= signerBalance;

        PromiseCreateArgs memory callWithdraw = near.call(token, "ft_transfer_call", args, 1, WITHDRAW_NEAR_GAS);
        bytes memory callbackArg = abi.encodeWithSelector(this.withdrawCallback.selector, msg.sender, token);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, 0, BASE_NEAR_GAS);

        callWithdraw.then(callback).transact();
    }

    function withdrawCallback(address signer, string calldata token, uint128 amount) external onlyRole(CALLBACK_ROLE) {
        require(
            AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful,
            "ERROR: The `Withdraw` XCC is fail"
        );

        uint128 transferredAmount = _stringToUint(AuroraSdk.promiseResult(0).output);
        balance[token][signer] += (amount - transferredAmount);

        if (transferredAmount > 0) {
            emit Withdraw(signer, token, transferredAmount);
        }
    }

    function _decodeTransferMessageFromBorsh(
        bytes memory transferMessageBorsh
    ) private pure returns (TransferMessage memory) {
        TransferMessage memory result;
        Borsh.Data memory borsh = Borsh.from(transferMessageBorsh);
        result.validTill = borsh.decodeU64();
        result.transferTokenAddressOnNear = string(borsh.decodeBytes());
        result.transferTokenAddressOnEth = address(borsh.decodeBytes20());
        result.transferTokenAmount = borsh.decodeU128();
        result.feeTokenAddressOnNear = string(borsh.decodeBytes());
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

    function getNearAddress() public view returns (string memory) {
        return string.concat(_addressToString(address(this)), ".", auroraEngineAccountIdOnNear);
    }

    function getTokenAuroraAddress(string calldata nearTokenAddress) external view returns (address) {
        return address(registeredTokens[nearTokenAddress]);
    }

    function getUserBalance(string calldata nearTokenAddress, address userAddress) external view returns (uint128) {
        return balance[nearTokenAddress][userAddress];
    }

    function _addressToString(address auroraAddress) private pure returns (string memory) {
        return Utils.bytesToHex(abi.encodePacked(auroraAddress));
    }

    function _stringToUint(bytes memory b) private pure returns (uint128) {
        uint128 result = 0;
        
        for (uint128 i = 0; i < b.length; i++) {
            uint128 v = uint128(uint8(b[i]));
            if (v >= 48 && v <= 57) {
                result = result * 10 + (v - 48);
            }
        }
        
        return result;
    }

    function _is_equal(string memory str1, string memory str2) private pure returns (bool) {
        return keccak256(abi.encodePacked(str1)) == keccak256(abi.encodePacked(str2));
    }

    /// Pauses all the operations in Fast Bridge. It affects only user-accessible operations.
    function pause() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        _pause();
    }

    /// Unpauses all the operations in Fast Bridge. It affects only user-accessible operations.
    function unPause() external onlyRole(UNPAUSABLE_ADMIN_ROLE) {
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
