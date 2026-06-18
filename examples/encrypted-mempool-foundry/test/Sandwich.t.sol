// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {MiniAMM} from "../src/MiniAMM.sol";

interface Vm { function prank(address) external; }
library console {
    address constant C = 0x000000000000000000636F6e736F6c652e6c6f67;
    function log(string memory a, uint256 b) internal view { C.staticcall(abi.encodeWithSignature("log(string,uint256)", a, b)); }
    function log(string memory a, int256 b)  internal view { C.staticcall(abi.encodeWithSignature("log(string,int256)", a, b)); }
}

/// Stage 1 (unencrypted mempool): the attacker sees the victim's pending swap and
/// sandwiches it (front-run -> victim -> back-run), ending with more token0 than it
/// started — real MEV — while the victim fills at a worse price. Stage 2 (encrypted
/// mempool): the victim's order is hidden until inclusion, so it fills fair and the
/// attacker has nothing to wrap. Attacker and victim are distinct pranked senders.
contract SandwichTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    address constant ATTACKER = address(0xA11CE);
    address constant VICTIM = address(0xB0B);
    uint256 constant R = 1000 ether;
    uint256 constant VICTIM_IN = 100 ether;
    uint256 constant ATTACKER_IN = 300 ether;

    function _fair(uint256 amtIn) internal pure returns (uint256) { return R - (R * R) / (R + amtIn); }

    function test_encrypted_mempool_prevents_the_sandwich() external {
        // Stage 1 — unencrypted mempool.
        MiniAMM amm = new MiniAMM(R, R);
        amm.fund0(ATTACKER, ATTACKER_IN);
        amm.fund0(VICTIM, VICTIM_IN);
        vm.prank(ATTACKER); uint256 atk1 = amm.swap0for1(ATTACKER_IN); // front-run
        vm.prank(VICTIM);   amm.swap0for1(VICTIM_IN);                  // victim, worse price
        vm.prank(ATTACKER); amm.swap1for0(atk1);                       // back-run
        uint256 victimClear = amm.bal1(VICTIM);
        int256 attackerProfit = int256(amm.bal0(ATTACKER)) - int256(ATTACKER_IN);

        // Stage 2 — encrypted mempool: victim hidden, attacker can't front-run.
        MiniAMM amm2 = new MiniAMM(R, R);
        amm2.fund0(VICTIM, VICTIM_IN);
        vm.prank(VICTIM); amm2.swap0for1(VICTIM_IN);
        uint256 victimEnc = amm2.bal1(VICTIM);

        console.log("victim out (unencrypted mp) ", victimClear);
        console.log("attacker MEV profit (token0)", attackerProfit);
        console.log("victim out (encrypted mp)   ", victimEnc);

        require(victimClear < victimEnc, "stage 1: victim should fill worse");
        require(attackerProfit > 0, "stage 1: attacker should profit");
        require(victimEnc == _fair(VICTIM_IN), "stage 2: victim should fill fair");
    }
}
