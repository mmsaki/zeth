// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Constant-product AMM (x*y=k, no fee) with internal per-account balances, so a
/// swap is attributed to its msg.sender and an attacker's MEV is a real balance gain.
contract MiniAMM {
    uint256 public r0;
    uint256 public r1;
    mapping(address => uint256) public bal0;
    mapping(address => uint256) public bal1;
    event Swap(address indexed who, bool zeroForOne, uint256 amountIn, uint256 amountOut);

    constructor(uint256 a, uint256 b) { r0 = a; r1 = b; }
    function fund0(address u, uint256 amt) external { bal0[u] += amt; }
    function swap0for1(uint256 amountIn) external returns (uint256 out) {
        bal0[msg.sender] -= amountIn;
        out = r1 - (r0 * r1) / (r0 + amountIn);
        r0 += amountIn; r1 -= out;
        bal1[msg.sender] += out;
        emit Swap(msg.sender, true, amountIn, out);
    }
    function swap1for0(uint256 amountIn) external returns (uint256 out) {
        bal1[msg.sender] -= amountIn;
        out = r0 - (r0 * r1) / (r1 + amountIn);
        r1 += amountIn; r0 -= out;
        bal0[msg.sender] += out;
        emit Swap(msg.sender, false, amountIn, out);
    }
}
