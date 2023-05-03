// SPDX-License-Identifier: MIT
pragma solidity 0.8.11;
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract EthErc20FastBridge is Initializable, UUPSUpgradeable, AccessControlUpgradeable, PausableUpgradeable {
    using SafeERC20 for IERC20;
    bytes32 public constant PAUSABLE_ADMIN_ROLE = keccak256("PAUSABLE_ADMIN_ROLE");
    bytes32 public constant UNPAUSABLE_ADMIN_ROLE = keccak256("UNPAUSABLE_ADMIN_ROLE");
    bytes32 public constant WHITELISTING_TOKENS_ADMIN_ROLE = keccak256("WHITELISTING_TOKENS_ADMIN_ROLE");

    mapping(address => bool) public whitelistedTokens;
    mapping(bytes32 => bool) public processedHashes;

    event SetTokens(address[] _tokens, bool[] _states);

    event TransferTokens(
        uint256 indexed _nonce,
        address _relayer,
        address _token,
        address _recipient,
        uint256 _amount,
        string _unlock_recipient,
        bytes32 indexed _transfer_id
    );

    event AddTokenToWhitelist(address token);

    event RemoveTokenFromWhitelist(address token);

    modifier isWhitelisted(address _token) {
        require(whitelistedTokens[_token], "Token not whitelisted!");
        _;
    }

    function initialize(address[] memory _tokens, bool[] memory _states) public initializer {
        __Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(WHITELISTING_TOKENS_ADMIN_ROLE, _msgSender());
        _setupRole(PAUSABLE_ADMIN_ROLE, _msgSender());
        _setupRole(UNPAUSABLE_ADMIN_ROLE, _msgSender());
        setWhitelistedTokens(_tokens, _states);
    }

/**
 * @dev Checks whether a token is whitelisted in Fast Bridge.
 * @param _token The address of the token to check.
 * @return A boolean indicating whether the token is whitelisted (`true`) or not (`false`).
 */
    function isTokenInWhitelist(address _token) external view returns (bool) {
        return whitelistedTokens[_token];
    }

    /// Pauses all the operations in Fast Bridge. It affects only user-accessible operations.
    function pause() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        _pause();
    }

    /// Unpauses all the operations in Fast Bridge. It affects only user-accessible operations.
    function unPause() external onlyRole(UNPAUSABLE_ADMIN_ROLE) {
        _unpause();
    }

    // Change the set of whitelisted tokens
    function setWhitelistedTokens(address[] memory _tokens, bool[] memory _states) public onlyRole(WHITELISTING_TOKENS_ADMIN_ROLE) {
        require(_tokens.length == _states.length, "Arrays must be equal");

        for (uint256 i = 0; i < _tokens.length; i++) {
            whitelistedTokens[_tokens[i]] = _states[i];
        }

        emit SetTokens(_tokens, _states);
    }

    /**
      * @dev Adds a token to the `whitelistedTokens` mapping.
      * @param _token The address of the token to be added to the whitelist.
      * Requirements:
      * - Caller must have the `WHITELISTING_TOKENS_ADMIN_ROLE`.
      * - Token must not already be whitelisted.
      * Effects:
      * - Updates the `whitelistedTokens` mapping to include the new token.
      * - Emits an `AddTokenToWhitelist` event with the address of the added token.
    */
    function addTokenToWhitelist(address _token) public onlyRole(WHITELISTING_TOKENS_ADMIN_ROLE) {
        require(!whitelistedTokens[_token], "Token already whitelisted!");
        whitelistedTokens[_token] = true;
        emit AddTokenToWhitelist(_token);
    }

    /**
      * @dev Removes a token from the `whitelistedTokens` mapping.
      * @param _token The address of the token to be removed from the whitelist.
      * Requirements:
      * - Caller must have the `WHITELISTING_TOKENS_ADMIN_ROLE`.
      * - Token must already be whitelisted.
      * Effects:
      * - Updates the `whitelistedTokens` mapping to remove the specified token.
      * - Emits a `RemoveTokenFromWhitelist` event with the address of the removed token.
    */
    function removeTokenFromWhitelist(address _token) public onlyRole(WHITELISTING_TOKENS_ADMIN_ROLE) {
        require(whitelistedTokens[_token], "Token not whitelisted!");
        whitelistedTokens[_token] = false;
        emit RemoveTokenFromWhitelist(_token);
    }

    /**
      * @dev Transfers ERC20 tokens or Ether to a specified recipient. This is a second step for the Fast Bridge transfer from the NEAR side. The relayer, that provides the liquidity using the function, may later claim it back on the NEAR side.
      * @param _token The address of the token to be transferred. Use `address(0)` for Ether transfers.
      * @param _recipient The address of the recipient to receive the tokens or Ether.
      * @param _nonce A unique number, an identifier of the NEAR transfer, to ensure the transaction is not processed more than once.
      * @param _amount The amount of tokens or Ether to be transferred.
      * @param _unlock_recipient The address of the unlock recipient, the one who will be able to claim the transaction and get tokens on the NEAR side. Usually, it represents the NEAR address of the relayer.
      * @param _valid_till_block_height The block height until which the transaction can be processed.
      * Requirements:
      * - Contract must not be paused.
      * - Token must be whitelisted.
      * - The transaction must not have already been processed.
      * - The recipient address must not be 0 and must not be the same as the sender.
      * - The amount must not be 0.
      * - The transaction must not have expired.
      * Effects:
      * - Transfers the specified amount of tokens or Ether to the recipient.
      * - Emits a `TransferTokens` event with the information about the transfer. After that, the `unlock_recipient` can use proof for this event to claim tokens on the NEAR side.
    */
    function transferTokens(
        address _token,
        address payable _recipient,
        uint256 _nonce,
        uint256 _amount,
        string calldata _unlock_recipient,
        uint256 _valid_till_block_height
    ) external payable whenNotPaused isWhitelisted(_token) {
        require(block.number < _valid_till_block_height, "Transfer expired");
        require(_recipient != address(0) && _recipient != msg.sender, "Wrong recipient provided");
        require(_amount != 0, "Wrong amount provided");

        bytes32 processedHash = keccak256(abi.encodePacked(_token, _recipient, _nonce, _amount));

        require(!processedHashes[processedHash], "This transaction has already been processed!");
        processedHashes[processedHash] = true;

        if (_token == address(0)) {
            require(_amount == msg.value, "Wrong ethers amount provided");
            _recipient.transfer(_amount);
        } else {
            require(msg.value == 0, "Ethers not accepted for ERC-20 transfers");
            IERC20 token = IERC20(_token);
            token.safeTransferFrom(msg.sender, _recipient, _amount);
        }
        // slither-disable-next-line reentrancy-events
        emit TransferTokens(_nonce, msg.sender, _token, _recipient, _amount, _unlock_recipient, processedHash);
    }

    /**
      * @dev Allows the contract owner to withdraw tokens accidentally transferred to this contract.
      * @param _token The address of the token to be withdrawn.
      * Requirements:
      * - The caller must have the `DEFAULT_ADMIN_ROLE`.
    */
    function withdrawStuckTokens(address _token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20 token = IERC20(_token);
        token.safeTransfer(msg.sender, token.balanceOf(address(this)));
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
