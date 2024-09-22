import json
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
        self.transaction_history = []

    def detect_reentrancy(self):
        current_balance = web3.eth.get_balance(self.vulnerable_contract.address)
        
        # 1. State Change Detection
        if current_balance < self.previous_balance:
            print("Potential reentrancy attack detected! Contract balance decreased.")
        else:
            print("No abnormal state change detected.")

        # 2. Transaction Dependencies Detection
        last_block = web3.eth.block_number
        block = web3.eth.getBlock(last_block, full_transactions=True)
        for tx in block.transactions:
            if tx.to == self.vulnerable_contract.address or tx.to == self.attacker_contract.address:
                self.transaction_history.append(tx)
                if self.is_suspicious_transaction(tx):
                    print(f"Suspicious transaction detected in block {last_block}: {tx.hash.hex()}")

        # Update balance after checking
        self.previous_balance = current_balance

    def is_suspicious_transaction(self, tx):
        # Check for rapid or recursive transactions
        for previous_tx in self.transaction_history:
            if previous_tx['to'] == tx['to'] and previous_tx['from'] == tx['from']:
                # If same address interacts multiple times in rapid succession, flag it
                return True
        return False

# Load deployed contracts
with open('deployed_contracts.json') as f:
    deployed_addresses = json.load(f)

vulnerable_contract = load_contract('VulnerableContract', deployed_addresses['VulnerableContract'])
attacker_contract = load_contract('Attacker', deployed_addresses['Attacker'])

# Create the detector instance
detector = ReentrancyDetector(vulnerable_contract, attacker_contract)

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

# Attack simulation (trigger the attack)
def simulate_attack(amount_ether):
    print(f"Simulating attack with {amount_ether} ETH")
    
    # Attacker initiates the attack
    tx_hash = attacker_contract.functions.attack(web3.toWei(amount_ether, 'ether')).transact({
        'from': web3.eth.accounts[1], 'value': web3.toWei(amount_ether, 'ether')
    })
    web3.eth.wait_for_transaction_receipt(tx_hash)

# Detect reentrancy after each transaction
def run_detection_cycle():
    detector.detect_reentrancy()

#check_and_deposit_funds(vulnerable_contract)

# Example simulation:
simulate_attack(1)  # Simulate an attack with 1 Ether
run_detection_cycle()  # Run detection after the attack

# Repeat this loop for ongoing detection
for i in range(5):
    simulate_attack(0.1)  # Simulate small attacks
    run_detection_cycle()  # Run detection after each attack
