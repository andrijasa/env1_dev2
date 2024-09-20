// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestFallback {
    event FallbackTriggered(uint256 balance);

    // Fallback function that gets triggered when the contract receives Ether
    fallback() external payable {
        emit FallbackTriggered(address(this).balance);
    }
}
