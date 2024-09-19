const SimpleVulnerableContract = artifacts.require("SimpleVulnerableContract");
const SimpleAttacker = artifacts.require("SimpleAttacker");

module.exports = async function (deployer, network, accounts) {
  // Deploy the vulnerable contract
  await deployer.deploy(SimpleVulnerableContract);
  const vulnerableInstance = await SimpleVulnerableContract.deployed();

  // Log the vulnerable contract address
  console.log("SimpleVulnerableContract deployed at:", vulnerableInstance.address);

  // Deploy the attacker contract with the vulnerable contract's address
  await deployer.deploy(SimpleAttacker, vulnerableInstance.address);
  const attackerInstance = await SimpleAttacker.deployed();

  // Log the attacker contract address
  console.log("SimpleAttacker deployed at:", attackerInstance.address);
  
  // Save contract details to a JSON file (optional)
  const fs = require('fs');
  const deployedContracts = {
    SimpleVulnerableContract: vulnerableInstance.address,
    SimpleAttacker: attackerInstance.address,
  };
  
  fs.writeFileSync('deployed_contracts.json', JSON.stringify(deployedContracts, null, 2));

  console.log("Contract addresses saved to deployed_contracts.json");
};
