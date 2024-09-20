from web3 import Web3
import json
import os

# Connect to Ganache or another Ethereum node
ganache_url = "http://127.0.0.1:7545"  # Replace with your own node URL if needed
web3 = Web3(Web3.HTTPProvider(ganache_url))
CONTRACTS_PATH = "./build/contracts"


# Ensure connection to the Ethereum network
if web3.isConnected():
    print("Connected to Ethereum node.")
else:
    raise Exception("Failed to connect to Ethereum node.")

# Set default account to send Ether from
sender_account = web3.eth.accounts[0]  # Use the first Ganache account

# Set default account to send Ether from
sender_account = web3.eth.accounts[0]  # Use the first Ganache account

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

TestFallback_contract = web3.eth.contract(
    address=Web3.toChecksumAddress(contracts['TestFallback']['address']),
    abi=contracts['TestFallback']['abi']
)
# Specify the amount of Ether to send (e.g., 1 Ether)
amount_to_send = web3.toWei(1, 'ether')

# Prepare the transaction
transaction = {
    'from': sender_account,
    'to': attacker_contract.address,
    'value': amount_to_send,
    'gas': 100000,  # Minimum gas for Ether transfer
    'gasPrice': web3.toWei('20', 'gwei')  # Adjust gas price if needed
}

# Send the transaction
tx_hash = web3.eth.send_transaction(transaction)

# Wait for transaction to be mined
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

# Output transaction details
print(f"Transaction successful with hash: {tx_hash.hex()}")
print(f"Transaction receipt: {tx_receipt}")

# Check the vulnerable contract balance after the transaction
contract_balance = web3.eth.get_balance(vulnerable_contract.address)
print(f"Vulnerable contract balance: {web3.fromWei(contract_balance, 'ether')} ETH")
