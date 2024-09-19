// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;

    // Deposit Ether into the contract
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable withdraw function with reentrancy vulnerability
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance99");

        // Vulnerability: sending Ether before updating the state
        (bool success, ) = msg.sender.call{value: _amount+1000}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= _amount;  // State updated after transfer
    }

    // Get contract's Ether balance
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
