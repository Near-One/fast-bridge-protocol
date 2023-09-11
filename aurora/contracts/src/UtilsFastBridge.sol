// SPDX-License-Identifier: CC-BY-1.0
pragma solidity ^0.8.17;

import {NEAR, PromiseCreateArgs} from "@auroraisnear/aurora-sdk/aurora-sdk/AuroraSdk.sol";
import {Utils as UtilsAuroraSdk} from "@auroraisnear/aurora-sdk/aurora-sdk/Utils.sol";

library UtilsFastBridge {
    uint128 constant ASCII_0 = 48;
    uint128 constant ASCII_9 = 57;

    function addressToString(address auroraAddress) internal pure returns (string memory) {
        return UtilsAuroraSdk.bytesToHex(abi.encodePacked(auroraAddress));
    }

    function stringToUint(bytes memory b) internal pure returns (uint128) {
        uint128 result = 0;

        for (uint128 i = 0; i < b.length; i++) {
            uint128 v = uint128(uint8(b[i]));

            if (v >= ASCII_0 && v <= ASCII_9) {
                result = result * 10 + (v - ASCII_0);
            }
        }

        return result;
    }

    function borshEncode(bytes memory value) internal pure returns (bytes memory) {
        return abi.encodePacked(UtilsAuroraSdk.swapBytes4(uint32(value.length)), value);
    }

    /// Creates a base promise. This is not immediately scheduled for execution
    /// until transact is called. It can be combined with other promises using
    /// `then` combinator.
    ///
    /// Input is not checekd during promise creation. If it is invalid, the
    /// transaction will be scheduled either way, but it will fail during execution.
    function callWithoutTransferWNear(
        NEAR storage _near,
        string memory targetAccountId,
        string memory method,
        bytes memory args,
        uint128 nearBalance,
        uint64 nearGas
    ) internal view returns (PromiseCreateArgs memory) {
        require(_near.initialized, "Near isn't initialized");
        return PromiseCreateArgs(targetAccountId, method, args, nearBalance, nearGas);
    }

    function isStrEqual(string memory str1, string memory str2) internal pure returns (bool) {
        return keccak256(abi.encodePacked(str1)) == keccak256(abi.encodePacked(str2));
    }
}
