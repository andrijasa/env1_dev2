// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw0(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount, bool success);

    // Deposit Ether into the contract
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Vulnerable withdraw function
    function withdraw(uint256 amount) public {
        uint256 vulnBalance = balances[msg.sender]; //address(this).balance; //

        require(vulnBalance >= amount, "Insufficient balance in contract");

        // Transfer Ether using .call to ensure enough gas is forwarded
        (bool success, ) = msg.sender.call{value: amount}("");
        // (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        // Update the balance after the transfer
        
        //balances[msg.sender] -= amount;
        vulnBalance = address(this).balance;
        emit Withdraw(msg.sender, amount, success);
    }

    // Allow the contract to receive Ether directly
    receive() external payable {}
}
