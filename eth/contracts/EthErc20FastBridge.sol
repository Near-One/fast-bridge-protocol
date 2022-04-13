// SPDX-License-Identifier: MIT
pragma solidity 0.8.11;
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";


contract EthErc20FastBridge is  Initializable, UUPSUpgradeable, AccessControlUpgradeable, PausableUpgradeable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    using SafeERC20 for IERC20;
    mapping (address => bool) public whitelistedTokens;
    mapping (bytes32 => bool) public processedHashes;
    
    event SetTokens(
        address[] _tokens,
        bool[] _states
    );

    event TransferTokens(
        address relayer,
        bytes32 processedHash
    );

    modifier isWhitelisted(address _token) {
        require(whitelistedTokens[_token], "Token not whitelisted!");
        _;
    }

    function initialize(
        address[] memory _tokens,
        bool[] memory _states
    ) 
        public
        initializer
    {   
        __Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();
        _setupRole(ADMIN_ROLE, _msgSender());
        setWhitelistedTokens(_tokens, _states);
    }

    function isTokenInWhitelist(address _token) external view returns(bool) {
        return whitelistedTokens[_token];
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unPause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    function setWhitelistedTokens(
        address[] memory _tokens,
        bool[] memory _states
    ) 
        public 
        onlyRole(ADMIN_ROLE) 
    {
        require(_tokens.length == _states.length, "Arrays must be equal");

        for (uint256 i = 0; i < _tokens.length; i++) {
            whitelistedTokens[_tokens[i]] = _states[i];
        }

        emit SetTokens(_tokens, _states);
    }   

    function transferTokens(
        address _token, 
        address _recipient, 
        uint256 _nonce,  
        uint256 _amount
    ) 
        external 
        whenNotPaused
        isWhitelisted(_token)
    {
        IERC20 token = IERC20(_token);
        bytes32 processedHash = keccak256(
            abi.encodePacked(_token, _recipient, _nonce, _amount));

        require(!processedHashes[processedHash], "This transaction has already been processed!");
        processedHashes[processedHash] = true;

        token.safeTransferFrom(msg.sender, _recipient, _amount);

        emit TransferTokens(msg.sender, processedHash);
    }

    function withdrawStuckTokens(
        address _token
    ) 
        external 
        onlyRole(ADMIN_ROLE) 
    {
        IERC20 token = IERC20(_token);
        token.safeTransfer(
            msg.sender, 
            token.balanceOf(address(this))
        );
    }

    function _authorizeUpgrade(
        address newImplementation
    ) 
        internal 
        override
        onlyRole(ADMIN_ROLE) 
    {

    }
}