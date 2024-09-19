from web3 import Web3
import json
import os

# Simulating Smart Contract and Ganache Blockchain Environment
ganache_url = "http://127.0.0.1:7545"
CONTRACTS_PATH = "./build/contracts"
# Connect to Ganache or Ethereum node
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Set default account to use for transactions
sender_account = web3.eth.accounts[0]

# Helper function to load contract ABIs and addresses
def load_contracts(path, deployed_addresses):
    contracts = {}
    for filename in os.listdir(path):
        if filename.endswith(".json"):
            with open(os.path.join(path, filename)) as f:
                contract_data = json.load(f)
                contract_name = filename.split(".")[0]
                if contract_name in deployed_addresses:
                    # Store contract object with ABI and address
                    contracts[contract_name] = {
                        'abi': contract_data['abi'],
                        'address': deployed_addresses[contract_name]
                    }
    return contracts

# Load deployed contract addresses from deployed_contracts.json
with open('deployed_contracts.json') as f:
    deployed_addresses = json.load(f)

# Load contracts from ABIs and addresses
contracts = load_contracts(CONTRACTS_PATH, deployed_addresses)

# Create contract instances using Web3
vulnerable_contract = web3.eth.contract(
    address=Web3.toChecksumAddress(contracts['VulnerableContract']['address']),
    abi=contracts['VulnerableContract']['abi']
)

attacker_contract = web3.eth.contract(
    address=Web3.toChecksumAddress(contracts['Attacker']['address']),
    abi=contracts['Attacker']['abi']
)

tx_value = int(web3.toWei(10, 'gwei'))  # Ensure integer
tx_gas = int(web3.toWei(100000, 'wei'))  # Ensure integer
tx_gas_price = int(web3.toWei('1', 'gwei'))  # Ensure integer
# Test the attack
try:
    tx_hash = attacker_contract.functions.attack().transact({
        'from': sender_account,
        'value': tx_value,
        'gas': tx_gas,
        'gasPrice': tx_gas_price
    })
    web3.eth.wait_for_transaction_receipt(tx_hash)
    print("Transaction successful!")
except Exception as e:
    print(f"Attack failed: {e}")
