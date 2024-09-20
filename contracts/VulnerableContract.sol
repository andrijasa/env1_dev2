// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;

    event TransferAttempt(address indexed to, uint256 amount, bool success);
    event ContractBalance(uint256 balance);
    event WithdrawFailure(string message);

    // Function to deposit Ether into the contract
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) public {
        emit ContractBalance(address(this).balance); // Log the contract's balance

        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // Attempt to send Ether
        // (bool success, ) = msg.sender.call{value: _amount-1000, gas: 5000000}("");
        // emit TransferAttempt(msg.sender, _amount, success); // Log the attempt

        // if (!success) {
        //     emit WithdrawFailure("Transfer failed due to unknown reasons");
        // }

        // require(success, "Transfer failed");

        balances[msg.sender] -= _amount;
    }

    // Get the contract's Ether balance
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
