// SPDX-License-Identifier: MIT
pragma solidity 0.8.11;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestToken is ERC20 {
    uint8 tokenDecimals;

    constructor(uint8 decimals, string memory name, string memory symbol) ERC20(name, symbol) {
        tokenDecimals = decimals;
    }

    function decimals() public view virtual override returns (uint8) {
        return tokenDecimals;
    }

    function mint(uint256 _amount) external {
        _mint(msg.sender, _amount);
    }
}
