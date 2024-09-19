// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleVulnerableContract {
    mapping(address => uint256) public balances;

    // Event for deposits
    event Deposit(address indexed user, uint256 amount);
    // Event for withdrawals
    event Withdraw(address indexed user, uint256 amount);

    // Deposit function to allow users to send Ether to the contract
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Withdraw function (vulnerable to reentrancy)
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // Vulnerable part: Ether is sent before balance is updated
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");

        // Update balance after sending Ether
        balances[msg.sender] -= _amount;
        emit Withdraw(msg.sender, _amount);
    }

    // Get the contract's balance
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    // Allow the contract to receive Ether
    receive() external payable {}
}
