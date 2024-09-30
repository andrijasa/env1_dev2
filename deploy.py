import json
import numpy as np
import os
from stable_baselines3 import PPO
from web3 import Web3

# Assuming ReentrancyEnv is already defined in trainv7
from reentrancyDetector import ReentrancyDetector
from reentrancyEnv import ReentrancyEnv
from severityScore import SeverityScore

# Load the best PPO model
model_path = "./model_saved/trained_model_33.97.zip"
model = PPO.load(model_path)

# Connect to a local Ethereum node (e.g., Ganache or a testnet node)
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))  # Update with your node's URL++

def check_and_deposit_funds(contract):
    balance = w3.eth.get_balance(contract.address)
    balance_in_ether = w3.fromWei(balance, 'ether')
    
    print(f"Vulnerable contract current balance: {balance_in_ether} ETH")
    
    if balance_in_ether < 1:
        deposit_amount = 1 - balance_in_ether
        print(f"Depositing {deposit_amount} Ether to the vulnerable contract.")
        tx_hash = contract.functions.deposit().transact({
            'from': w3.eth.accounts[0], 'value': w3.toWei(deposit_amount, 'ether')
        })
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print("Deposit complete, vulnerable contract balance is now above 1 ETH.")

def simulate_targeted_attack(amount_ether, target_drain_ether, target_contract, attacker_contract, web3):
    print(f"Simulating attack with {amount_ether} ETH, targeting to drain {target_drain_ether} ETH")
    vulnerable_balance_before = web3.eth.get_balance(target_contract.address)
    attacker_balance = web3.eth.get_balance(web3.eth.accounts[1])
    required_amount = web3.toWei(amount_ether, 'ether')
    target_drain_amount = web3.toWei(target_drain_ether, 'ether')

    if attacker_balance < required_amount:
        print("Attacker does not have enough Ether to perform the attack.")
        return False, 0, 0  # Return false indicating the attack couldn't proceed

    gas_limit = 5000000  # Set the gas limit

    try:
        tx_hash = attacker_contract.functions.attack(target_drain_amount).transact({
            'from': web3.eth.accounts[1],
            'value': required_amount,
            'gas': gas_limit
        })
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print("Attack transaction mined.")

        # Check balances after the attack
        vulnerable_balance_after = web3.eth.get_balance(target_contract.address)
        #attacker_balance_after = web3.eth.get_balance(web3.eth.accounts[1])
        funds_drained = vulnerable_balance_before - vulnerable_balance_after
        receipt = web3.eth.getTransactionReceipt(tx_hash)
        gas_used = receipt.gasUsed  # Retrieve the gas used from the transaction receipt

        # Instantiate the ReentrancyDetector
        detector = ReentrancyDetector(web3, target_contract)

        # Pass the tx_hash as an argument to the method using the instance
        call_count, call_depth = detector.analyze_transaction(tx_hash)
        # Calculate severity scores based on the attack profile
        funds_severity = SeverityScore._calculate_funds_severity(funds_drained)
        call_count_severity = SeverityScore._calculate_call_count_severity(call_count)
        call_depth_severity = SeverityScore._calculate_call_depth_severity(call_depth)
        gas_used_severity = SeverityScore._calculate_gas_severity(gas_used)

        # Total severity score for the attack
        severity_score = funds_severity + call_count_severity + call_depth_severity + gas_used_severity

        print(f"Attack: {True}, Call count: {call_count}, Call depth: {call_depth}, Funds drained: {web3.fromWei(funds_drained, 'ether')} ETH, Gas used: {gas_used}, Severity score: {severity_score}")


        return True, funds_drained, gas_used, call_count, call_depth, severity_score

    except ValueError as e:
        # Handle the case where the transaction was blocked by the middleware
        print(f"Transaction blocked by middleware: {e}")
        return False, 0, 0, 0, 0, 0  # Indicate that the transaction was blocked and no funds were drained

def normalize_value(value, max_value):
    """ Normalizes a value to be between 0 and 1 based on a maximum possible value """
    return value / max_value if max_value != 0 else 0

# Function to test a smart contract for reentrancy
def test_contract(target_contract, attacker_contract):
    """
    Tests the given contract address for reentrancy using the PPO model.
    """
    # Example normalization constants, adjust based on your environment
    MAX_BALANCE = w3.toWei(10, 'ether')  # Assume a max balance of 10 Ether
    MAX_FUNDS_DRAINED = w3.toWei(1, 'ether')  # Assume a max drain of 1 Ether
    MAX_GAS_USED = 500000  # Example max gas used
    MAX_CALL_COUNT = 10  # Example max call count
    MAX_CALL_DEPTH = 10  # Example max call depth
    
    # Get balances
    

    check_and_deposit_funds(target_contract)
    target_contract_balance = w3.eth.get_balance(target_contract.address)
    attacker_balance = w3.eth.get_balance(w3.eth.accounts[1])
    attack, funds_drained, gas_used, call_count, call_depth, severity_score = simulate_targeted_attack(0.0001, 0.0005, target_contract,  attacker_contract, w3)
    
    print(f"Attack: {attack}, Call count: {call_count}, Call depth: {call_depth}, Funds drained: {w3.fromWei(funds_drained, 'ether')} ETH, Gas used: {gas_used}, Severity score: {severity_score}")


    # Normalize all values to be in the range [0, 1]
    normalized_reentrancy_detected = 1 if attack else 0  # 1 if attack was successful, otherwise 0
    normalized_target_contract_balance = normalize_value(target_contract_balance, MAX_BALANCE)
    normalized_attacker_balance = normalize_value(attacker_balance, MAX_BALANCE)
    normalized_funds_drained = normalize_value(funds_drained, MAX_FUNDS_DRAINED)
    normalized_gas_used = normalize_value(gas_used, MAX_GAS_USED)
    normalized_call_count = normalize_value(call_count, MAX_CALL_COUNT)
    normalized_call_depth = normalize_value(call_depth, MAX_CALL_DEPTH)

    # Set the initial state, including the new variables
    state = np.array([
        normalized_reentrancy_detected,
        normalized_target_contract_balance,
        normalized_attacker_balance,
        normalized_funds_drained,
        normalized_gas_used,
        normalized_call_count,
        normalized_call_depth,
        severity_score,
        0  # No action taken yet
    ], dtype=np.float32)

    # The environment step might expect an observation space like the one in ReentrancyEnv
    observation = state.reshape(1, -1)  # Reshape to match model's input shape
    
    # Use the PPO model to predict whether reentrancy is detected
    action, _states = model.predict(observation)
    
    return action  # Assuming action 0 = prevent (no reentrancy), action 1 = allow (reentrancy detected)

# Load the ABI for the contracts
def load_contract_abi(contract_name):
    with open(f'./build/contracts/{contract_name}.json') as f:
        return json.load(f)['abi']

# Load contract instances
def load_contract(contract_name, contract_address):
    abi = load_contract_abi(contract_name)
    return w3.eth.contract(address=Web3.toChecksumAddress(contract_address), abi=abi)

# Load deployed contracts
with open('deployed_contracts.json') as f:
    deployed_addresses = json.load(f)

# vulnerable_contract = load_contract('VulnerableContract', deployed_addresses['VulnerableContract'])
# attacker_contract = load_contract('Attacker', deployed_addresses['Attacker'])

vulnerable_contract = load_contract('SafeBank', deployed_addresses['SafeBank'])
attacker_contract = load_contract('AttackerSafeBank', deployed_addresses['AttackerSafeBank'])

target_contract = vulnerable_contract  # Change this to the contract you want to test
print(f"Testing contract: {target_contract}")

# Check and deposit funds if needed
print(f"Vulnerable contract current balance: {w3.fromWei(w3.eth.get_balance(target_contract.address), 'ether')} ETH")
print(f"Attacker contract current balance: {w3.fromWei(w3.eth.get_balance(attacker_contract.address), 'ether')} ETH")

action = test_contract(target_contract, attacker_contract)

if action == 1:
    print(f"Contract {target_contract.address} passed: No reentrancy detected.")
else:
    print(f"Contract {target_contract.address} failed: Reentrancy detected!")

# Check and deposit funds if needed
print(f"Vulnerable contract current balance: {w3.fromWei(w3.eth.get_balance(target_contract.address), 'ether')} ETH")
print(f"Attacker contract current balance: {w3.fromWei(w3.eth.get_balance(attacker_contract.address), 'ether')} ETH")
