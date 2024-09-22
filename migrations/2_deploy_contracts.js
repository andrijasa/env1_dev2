const fs = require('fs');

const VulnerableContract = artifacts.require("VulnerableContract");
const Attacker = artifacts.require("Attacker");
//const TestFallback = artifacts.require("TestFallback");

module.exports = async function (deployer) {
  // Object to store contract information
  let deployedContracts = {};

  // Deploy VulnerableContract and get the deployed address
  await deployer.deploy(VulnerableContract);
  const vulnerableContractInstance = await VulnerableContract.deployed();
  deployedContracts[VulnerableContract.contractName] = vulnerableContractInstance.address;

  // Deploy Attacker and get the deployed address
  await deployer.deploy(Attacker, vulnerableContractInstance.address);
  const attackerContractInstance = await Attacker.deployed();
  deployedContracts[Attacker.contractName] = attackerContractInstance.address;

  // // Deploy VulnerableContract and get the deployed address
  // await deployer.deploy(TestFallback);
  // const TestFallbackInstance = await TestFallback.deployed();
  // deployedContracts[TestFallback.contractName] = TestFallbackInstance.address;


  // Write the deployed contract addresses to a JSON file
  const outputPath = './deployed_contracts.json';
  fs.writeFileSync(outputPath, JSON.stringify(deployedContracts, null, 2));

  console.log(`Contracts deployed and addresses saved to ${outputPath}`);
};
