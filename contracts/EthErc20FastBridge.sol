// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.11;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";


contract EthErc20FastBridge is Ownable {
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

    function isTokenInWhitelist(address _token) external returns(bool) {
        return whitelistedTokens[_token];
    }

    function setWhitelistedTokens(
        address[] memory _tokens,
        bool[] memory _states
    ) 
        public 
        onlyOwner 
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
        isWhitelisted(_token)
    {
        IERC20 token = IERC20(_token);
        bytes32 processedHash = keccak256(
            abi.encodePacked(_token, _recipient, _nonce, _amount));
        
        if (!processedHashes[processedHash]) {
            token.safeTransferFrom(msg.sender, _recipient, _amount);
            processedHashes[processedHash] = true;

            emit TransferTokens(msg.sender, processedHash);
        }
    }

    function withdrawStuckTokens(address _token) external onlyOwner {
        IERC20 token = IERC20(_token);
        token.safeTransfer(
            msg.sender, 
            token.balanceOf(address(this))
        );
    }

    receive() external payable {
        payable(msg.sender).transfer(msg.value);
    }
}