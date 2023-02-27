pragma solidity ^0.8.17;

import {IERC20 as IERC20_NEAR} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import "../lib/aurora-engine/etc/eth-contracts/contracts/EvmErc20.sol";
import {AuroraSdk, NEAR, PromiseCreateArgs} from "../lib/aurora-solidity-sdk/src/AuroraSdk.sol";
import "../lib/aurora-solidity-sdk/src/Borsh.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";

uint64 constant SET_NEAR_GAS = 36_000_000_000_000;
uint64 constant INIT_NEAR_GAS = 100_000_000_000_000;

contract AuroraErc20FastBridge {
    using AuroraSdk for NEAR;
    using AuroraSdk for PromiseCreateArgs;
    using Borsh for Borsh.Data;

    address creator;
    NEAR public near;
    EvmErc20 public usdc;

    constructor() {
        creator = msg.sender;
        near = AuroraSdk.initNear(IERC20_NEAR(0x4861825E75ab14553E5aF711EbbE6873d369d146));
        usdc = EvmErc20(0x901fb725c106E182614105335ad0E230c91B67C8);
    }
}
