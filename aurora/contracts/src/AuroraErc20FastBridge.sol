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
    uint64 constant UNLOCK_NEAR_GAS = 160_000_000_000_000;

    uint128 constant NEAR_STORAGE_DEPOSIT = 12_500_000_000_000_000_000_000;

    uint128 constant ASCII_0 = 48;
    uint128 constant ASCII_9 = 57;
    uint128 constant ONE_YOCTO = 1;
    uint128 constant NO_DEPOSIT = 0;

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

    function registerToken(
        address auroraTokenAddress,
        string calldata nearTokenAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
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
        require(near.wNEAR.balanceOf(address(this)) >= ONE_YOCTO, "Not enough wNEAR balance");
        require(isUserWhitelisted(address(msg.sender)), "Sender not whitelisted!");
        TransferMessage memory transferMessage = _decodeTransferMessageFromBorsh(initTransferArgs);
        require(
            transferMessage.auroraSender == msg.sender,
            "Aurora sender in transfer message doesn't equal to signer"
        );

        require(
            _isStrEqual(transferMessage.transferTokenAddressOnNear, transferMessage.feeTokenAddressOnNear),
            "The transfer and fee tokens are different. Different tokens not supported yet."
        );

        IEvmErc20 token = registeredTokens[transferMessage.transferTokenAddressOnNear];
        require(address(token) != address(0), "The token is not registered!");

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

        PromiseCreateArgs memory callFtTransfer = _callWithoutTransferWNear(
            near,
            transferMessage.transferTokenAddressOnNear,
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
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, NO_DEPOSIT, BASE_NEAR_GAS);

        callFtTransfer.then(callback).transact();
    }

    function initTokenTransferCallback(
        address signer,
        bytes calldata initTransferArgs
    ) external onlyRole(CALLBACK_ROLE) {
        uint128 transferredAmount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferredAmount = _stringToUint(AuroraSdk.promiseResult(0).output);
        }

        TransferMessage memory transferMessage = _decodeTransferMessageFromBorsh(initTransferArgs);

        uint128 refundAmount = (transferMessage.transferTokenAmount +
            transferMessage.feeTokenAmount -
            transferredAmount);
        if (refundAmount > 0) {
            balance[transferMessage.transferTokenAddressOnNear][signer] += refundAmount;
        }

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

        PromiseCreateArgs memory callUnlock = near.call(
            bridgeAddressOnNear,
            "unlock_and_withdraw",
            args,
            NO_DEPOSIT,
            UNLOCK_NEAR_GAS
        );
        bytes memory callbackArg = abi.encodeWithSelector(this.unlockCallback.selector, nonce);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, NO_DEPOSIT, BASE_NEAR_GAS);

        callUnlock.then(callback).transact();
    }

    function unlockCallback(uint128 nonce) external onlyRole(CALLBACK_ROLE) {
        require(AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful, "ERROR: The `Unlock` XCC is fail");

        TransferMessage memory transferMessage = _decodeTransferMessageFromBorsh(AuroraSdk.promiseResult(0).output);

        balance[transferMessage.transferTokenAddressOnNear][transferMessage.auroraSender] += transferMessage
            .transferTokenAmount;
        balance[transferMessage.feeTokenAddressOnNear][transferMessage.auroraSender] += transferMessage.feeTokenAmount;

        emit Unlock(
            nonce,
            transferMessage.auroraSender,
            transferMessage.transferTokenAddressOnNear,
            transferMessage.transferTokenAmount,
            transferMessage.feeTokenAddressOnNear,
            transferMessage.feeTokenAmount
        );
    }

    function withdraw(string calldata token) external whenNotPaused {
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
                _addressToString(msg.sender),
                '"}'
            )
        );
        balance[token][msg.sender] -= signerBalance;

        PromiseCreateArgs memory callWithdraw = _callWithoutTransferWNear(
            near,
            token,
            "ft_transfer_call",
            args,
            ONE_YOCTO,
            WITHDRAW_NEAR_GAS
        );
        bytes memory callbackArg = abi.encodeWithSelector(this.withdrawCallback.selector, msg.sender, token);
        PromiseCreateArgs memory callback = near.auroraCall(address(this), callbackArg, NO_DEPOSIT, BASE_NEAR_GAS);

        callWithdraw.then(callback).transact();
    }

    function withdrawCallback(address signer, string calldata token, uint128 amount) external onlyRole(CALLBACK_ROLE) {
        uint128 transferredAmount = 0;

        if (AuroraSdk.promiseResult(0).status == PromiseResultStatus.Successful) {
            transferredAmount = _stringToUint(AuroraSdk.promiseResult(0).output);
        }

        uint128 refundAmount = amount - transferredAmount;

        if (refundAmount > 0) {
            balance[token][signer] += refundAmount;
        }

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

            if (v >= ASCII_0 && v <= ASCII_9) {
                result = result * 10 + (v - ASCII_0);
            }
        }

        return result;
    }

    /// Creates a base promise. This is not immediately scheduled for execution
    /// until transact is called. It can be combined with other promises using
    /// `then` combinator.
    ///
    /// Input is not checekd during promise creation. If it is invalid, the
    /// transaction will be scheduled either way, but it will fail during execution.
    function _callWithoutTransferWNear(
        NEAR storage _near,
        string memory targetAccountId,
        string memory method,
        bytes memory args,
        uint128 nearBalance,
        uint64 nearGas
    ) private view returns (PromiseCreateArgs memory) {
        require(_near.initialized, "Near isn't initialized");
        return PromiseCreateArgs(targetAccountId, method, args, nearBalance, nearGas);
    }

    function _isStrEqual(string memory str1, string memory str2) private pure returns (bool) {
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
