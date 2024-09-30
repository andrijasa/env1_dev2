// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeBank {
    mapping(address => uint256) public balances;

    // Function to deposit Ether into the contract
    function deposit() external payable {
        require(msg.value > 0, "Must deposit some Ether");
        balances[msg.sender] += msg.value;
    }

    // Safe withdrawal function using Checks-Effects-Interactions pattern
    function withdraw(uint256 amount) external {
        uint256 balVulnerable;
        balVulnerable = balances[msg.sender];
        require(amount <= balVulnerable, "Insufficient balance");

        // Step 1: Check the condition (require statement above)
        
        // Step 2: Effects - Update the state before making any external calls
        balances[msg.sender] -= amount;

        // Step 3: Interactions - Send the Ether
        // Using the `call` method to transfer Ether, which is the recommended way in Solidity
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdrawal failed");
    }

    // Function to check the balance of an address
    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
