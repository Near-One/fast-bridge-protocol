// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.11;
import "@openzeppelin/contracts/access/Ownable.sol";


contract EthErc20FastBridge is Ownable {
    mapping (address => bool) public whitelistedTokens;
    
    event SetTokens(
        address[] _tokens,
        bool[] _states
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
    
}