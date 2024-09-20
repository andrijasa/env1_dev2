import json
import time
from web3 import Web3

# Connect to Ganache or a local Ethereum node
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))
web3.eth.default_account = web3.eth.accounts[0]

# Load the ABI for the contracts
def load_contract_abi(contract_name):
    with open(f'./build/contracts/{contract_name}.json') as f:
        return json.load(f)['abi']

# Load contract instances
def load_contract(contract_name, contract_address):
    abi = load_contract_abi(contract_name)
    return web3.eth.contract(address=Web3.toChecksumAddress(contract_address), abi=abi)

# Detect reentrancy attack based on state changes and transaction dependencies
class ReentrancyDetector:
    def __init__(self, vulnerable_contract, attacker_contract):
        self.vulnerable_contract = vulnerable_contract
        self.attacker_contract = attacker_contract
        self.previous_balance = web3.eth.get_balance(vulnerable_contract.address)
        self.balance_diffs = []  # Track balance differences across multiple transactions
        self.transaction_history = []

    def detect_reentrancy(self):
        # Add a small delay to ensure the transaction has processed
       # time.sleep(2)

        # Check the vulnerable contract's balance before and after the transaction
        current_balance = web3.eth.get_balance(self.vulnerable_contract.address)
        balance_diff = self.previous_balance - current_balance

        # Convert balances to Gwei for printing
        previous_balance_gwei = web3.toWei(self.previous_balance, 'wei')
        current_balance_gwei = web3.toWei(current_balance, 'wei')

        print(f"Previous balance: {previous_balance_gwei} wei")
        print(f"Current balance: {current_balance_gwei} wei")

        # Check if balance_diff is positive before converting
        if balance_diff > 0:
            balance_diff_gwei = web3.toWei(balance_diff, 'wei')
            print(f"Potential reentrancy attack detected! Contract balance decreased by {balance_diff_gwei} wei.")
            self.balance_diffs.append(balance_diff)  # Track balance reduction
        else:
            print("No abnormal state change detected.")

        # Update balance after checking
        self.previous_balance = current_balance


# Load deployed contracts
with open('deployed_contracts.json') as f:
    deployed_addresses = json.load(f)

vulnerable_contract = load_contract('VulnerableContract', deployed_addresses['VulnerableContract'])
attacker_contract = load_contract('Attacker', deployed_addresses['Attacker'])

detector = ReentrancyDetector(vulnerable_contract, attacker_contract)

# Check if the vulnerable contract has less than 5 Ether, and deposit 5 Ether if needed
def check_and_deposit_funds(contract):
    balance = web3.eth.get_balance(contract.address)
    balance_in_ether = web3.fromWei(balance, 'ether')
    
    print(f"Vulnerable contract current balance: {balance_in_ether} ETH")
    
    if balance_in_ether < 1:
        deposit_amount = 1 - balance_in_ether
        print(f"Depositing {deposit_amount} Ether to the vulnerable contract.")
        tx_hash = contract.functions.deposit().transact({
            'from': web3.eth.accounts[0], 'value': web3.toWei(deposit_amount, 'ether')
        })
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print("Deposit complete, vulnerable contract balance is now above 1 ETH.")

    # balance = web3.eth.get_balance(attacker_contract.address)
    # balance_in_ether = web3.fromWei(balance, 'ether')
    
    # print(f"Attacker contract current balance: {balance_in_ether} ETH")
    
    # if balance_in_ether < 1:
    #     deposit_amount = 1 - balance_in_ether
    #     print(f"Depositing {deposit_amount} Ether to the attacker contract.")
    #     tx_hash = attacker_contract.functions.deposit().transact({
    #         'from': web3.eth.accounts[0], 'value': web3.toWei(deposit_amount, 'ether')
    #     })
    #     web3.eth.wait_for_transaction_receipt(tx_hash)
    #     print("Deposit complete, attacker contract balance is now above 1 ETH.")    

# Attack simulation (trigger the attack)
def simulate_attack(amount_gwei):
    # formatted_amount = "{:.12f}".format(web3.fromWei(amount_gwei, 'ether'))
    print(f"\nSimulating attack with {amount_gwei} wei")
    
    # Check contract balance before attack
    balance_before = web3.eth.get_balance(vulnerable_contract.address)
    print(f"Vulnerable contract balance before attack: {web3.toWei(balance_before, 'wei')} wei")
    
    # Attacker initiates the attack
    tx_hash = attacker_contract.functions.attack(amount_gwei).transact({
        'from': web3.eth.accounts[1], 'value': amount_gwei, 'gas': 5000000  # Increased gas limit
    })
    
    
    # Wait for transaction to be mined
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Attack transaction mined in block {receipt.blockNumber}")

    # Check contract balance after attack
    balance_after = web3.eth.get_balance(vulnerable_contract.address)
    print(f"Vulnerable contract balance after attack: {web3.toWei(balance_after, 'wei')} wei")

# Detect reentrancy after each transaction
def run_detection_cycle():
    detector.detect_reentrancy()

# Check the balance of the vulnerable contract and deposit 5 ETH if needed
check_and_deposit_funds(vulnerable_contract)
# check_and_deposit_funds(attacker_contract)

# Example simulation:
simulate_attack(web3.toWei(0.1, 'ether'))  # Simulate an attack with 1000 Gwei
run_detection_cycle()  # Run detection after the attack

# Repeat this loop for recursive attacks with 100 Gwei
for i in range(3):
    simulate_attack(web3.toWei(0.01, 'ether'))  # Simulate small attacks with 100 Gwei
    run_detection_cycle()  # Run detection after each attack

# Final balance difference report
tracked_balance_diffs = [web3.fromWei(bal_diff, 'gwei') for bal_diff in detector.balance_diffs]
print(f"\nTracked balance differences over multiple transactions: {tracked_balance_diffs} Gwei")
