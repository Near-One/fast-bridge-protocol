pragma solidity ^0.8.17;

import {IERC20 as IERC20_NEAR} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import "aurora-engine/etc/eth-contracts/contracts/EvmErc20.sol";
import {AuroraSdk, NEAR, PromiseCreateArgs} from "aurora-solidity-sdk/AuroraSdk.sol";
import "aurora-solidity-sdk/Borsh.sol";
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
    event Log(string msg);

    constructor() {
        creator = msg.sender;
        near = AuroraSdk.initNear(IERC20_NEAR(0x4861825E75ab14553E5aF711EbbE6873d369d146));
        usdc = EvmErc20(0x901fb725c106E182614105335ad0E230c91B67C8);
    }

    function init_near_contract() public {
        emit NearContractInit(string(get_near_address()));

        PromiseCreateArgs memory callInc = near.call("dev-1676024144404-59802219762521", "increment", "", 0, INC_NEAR_GAS);
        callInc.transact();
    }

    function init_token_transfer(bytes memory init_transfer_args) public {
        Borsh.Data memory borsh = Borsh.from(init_transfer_args);
        borsh.decodeU64(); //valid_till
        borsh.decodeBytes(); //transfer token address on Near
        borsh.decodeBytes20(); //transfer token address on Ethereum
        uint128 transfer_token_amount = borsh.decodeU128();
        borsh.decodeBytes(); // fee token address on Near
        uint128 fee_token_amount = borsh.decodeU128();

        usdc.transferFrom(msg.sender, address(this), uint256(transfer_token_amount + fee_token_amount));
        usdc.withdrawToNear(get_near_address(), uint256(transfer_token_amount + fee_token_amount));
        near.wNEAR.transferFrom(msg.sender, address(this), uint256(1));

        string memory init_args_base64 = Base64.encode(init_transfer_args);
        bytes memory args = bytes(string.concat('{"receiver_id": "fb.olga24912_3.testnet", "amount": "', Strings.toString(transfer_token_amount + fee_token_amount), '", "msg": "', init_args_base64, '"}'));

        PromiseCreateArgs memory callTr = near.call("07865c6e87b9f70255377e024ace6630c1eaa37f.factory.goerli.testnet", "ft_transfer_call", args, 1, INIT_NEAR_GAS);
        callTr.transact();
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
