pragma solidity ^0.8.17;

import {IERC20 as IERC20_NEAR} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import "../lib/aurora-engine/etc/eth-contracts/contracts/EvmErc20.sol";
import {AuroraSdk, NEAR, PromiseCreateArgs} from "../lib/aurora-solidity-sdk/src/AuroraSdk.sol";
import "../lib/aurora-solidity-sdk/src/Borsh.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";

uint64 constant INC_NEAR_GAS = 36_000_000_000_000;
uint64 constant INIT_NEAR_GAS = 100_000_000_000_000;

contract AuroraErc20FastBridge {
    using AuroraSdk for NEAR;
    using AuroraSdk for PromiseCreateArgs;
    using Borsh for Borsh.Data;

    address creator;
    NEAR public near;
    EvmErc20 public usdc;

    event NearContractInit(string near_addres);
    event LogInt(uint64 msg);

    constructor() {
        creator = msg.sender;
        near = AuroraSdk.initNear(IERC20_NEAR(0x4861825E75ab14553E5aF711EbbE6873d369d146));
        usdc = EvmErc20(0x901fb725c106E182614105335ad0E230c91B67C8);
    }

    function init_near_contract() public {
        PromiseCreateArgs memory callInc = near.call("dev-1676024144404-59802219762521", "increment", "", 0, INC_NEAR_GAS);
        callInc.transact();

        emit NearContractInit(string(get_near_address()));
    }

    function init_token_transfer(bytes memory init_transfer_args) public {
        Borsh.Data memory borsh = Borsh.from(init_transfer_args);
        uint64 valid_till = borsh.decodeU64();

        emit LogInt(valid_till);
    }

    function get_near_address() public view returns (bytes memory) {
        bytes memory near_address_raw = bytes(string.concat(Strings.toHexString(uint160(address(this))), ".aurora"));
        bytes memory near_address = new bytes(near_address_raw.length - 2);

        for (uint256 i = 0; i < near_address_raw.length - 2; ++i) {
            near_address[i] = near_address_raw[i + 2];
        }

        return near_address;
    }

    function destruct() public {
        // Destroys this contract and sends remaining funds back to creator
        if (msg.sender == creator)
            selfdestruct(payable(creator));
    }
}
