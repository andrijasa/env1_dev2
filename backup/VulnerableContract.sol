// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;

    // Define events
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    // Deposit Ether into the contract
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);  // Emit Deposit event
    }

    // Vulnerable withdraw function using transfer (without state update first)
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // Vulnerability: transferring Ether before updating the balance
        payable(msg.sender).transfer(_amount);

        // State update happens after transfer, making it vulnerable
        balances[msg.sender] -= _amount;

        emit Withdraw(msg.sender, _amount);  // Emit Withdraw event
    }

    // Allow the contract to receive Ether directly
    receive() external payable {
        // Accept ETH sent directly to the contract
    }

    // Get contract's Ether balance
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
