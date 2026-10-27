// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Lib.sol";

contract Counter {
    uint256 public count;
    function inc() external { count = Lib.add1(count); }
}
