// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;

    event TransferAttempt(address indexed to, uint256 amount, bool success);
    event ContractBalance(uint256 balance);
    event SenderBalance(uint256 balance);
    event BalanceAtDeposit(uint256 attackerBalance, uint256 vulnerableBalance);
    event WithdrawFailure(string message);
    event DepositFromAttacker(string message);
    event WithdrawFromAttacker(string message);


    // Function to deposit Ether into the contract
    function deposit() public payable {
        
        balances[msg.sender] += msg.value;
        emit DepositFromAttacker("Deposit from attacker"); // Log the contract's balance
        emit BalanceAtDeposit(balances[msg.sender], address(this).balance);
    }

    function withdraw(uint256 _amount) public {
        emit DepositFromAttacker("Withdraw from attacker");
        emit ContractBalance(address(this).balance); // Log the contract's balance

        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // Attempt to send Ether
        (bool success, ) = msg.sender.call{value: _amount, gas: 2300}("");
        // emit TransferAttempt(msg.sender, _amount, success); // Log the attempt

        // if (!success) {
        //     emit WithdrawFailure("Transfer failed due to unknown reasons");
        // }

        require(success, "Transfer failed");

        balances[msg.sender] -= _amount;
        emit SenderBalance(balances[msg.sender]);
    }

    // Get the contract's Ether balance
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
