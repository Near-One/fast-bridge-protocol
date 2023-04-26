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

    // Check if token allowed to transfer in Fast Bridge
    function isTokenInWhitelist(address _token) external view returns (bool) {
        return whitelistedTokens[_token];
    }

    // Pause Fast Bridge
    function pause() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        _pause();
    }

    // Unpause Fast Bridge
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

    // Add token to whitelist
    function addTokenToWhitelist(address _token) public onlyRole(WHITELISTING_TOKENS_ADMIN_ROLE) {
        require(!whitelistedTokens[_token], "Token already whitelisted!");
        whitelistedTokens[_token] = true;
        emit AddTokenToWhitelist(_token);
    }

    // Remove token from whitelist
    function removeTokenFromWhitelist(address _token) public onlyRole(WHITELISTING_TOKENS_ADMIN_ROLE) {
        require(whitelistedTokens[_token], "Token not whitelisted!");
        whitelistedTokens[_token] = false;
        emit RemoveTokenFromWhitelist(_token);
    }

    // Transfer tokens on Ethereum side
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

    // Withdraw tokens accidentally transferred to this contract
    function withdrawStuckTokens(address _token) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20 token = IERC20(_token);
        token.safeTransfer(msg.sender, token.balanceOf(address(this)));
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
