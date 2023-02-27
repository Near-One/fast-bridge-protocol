// SPDX-License-Identifier: MIT
pragma solidity 0.8.11;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestToken is ERC20 {
    uint8 tokenDecimals;

    constructor(uint8 _decimals, string memory _name, string memory _symbol) ERC20(_name, _symbol) {
        tokenDecimals = _decimals;
    }

    function decimals() public view virtual override returns (uint8) {
        return tokenDecimals;
    }

    function mint(uint256 _amount) external {
        _mint(msg.sender, _amount);
    }
}
