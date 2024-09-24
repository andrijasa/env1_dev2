import json
from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.datastructures import AttributeDict

# Connect to Ganache or a local Ethereum node
ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)
web3.eth.default_account = web3.eth.accounts[0]

# Load the ABI for the contracts
def load_contract_abi(contract_name):
    with open(f'./build/contracts/{contract_name}.json') as f:
        return json.load(f)['abi']

# Load contract instances
def load_contract(contract_name, contract_address):
    abi = load_contract_abi(contract_name)
    return web3.eth.contract(address=Web3.toChecksumAddress(contract_address), abi=abi)

def convert_attribute_dict(obj):
        if isinstance(obj, AttributeDict):
            return {k: convert_attribute_dict(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_attribute_dict(i) for i in obj]
        else:
            return obj

class ReentrancyDetector:
    def __init__(self, vulnerable_contract):
        self.vulnerable_contract = vulnerable_contract
        self.previous_block = web3.eth.block_number

    def detect_reentrancy(self):
        # Get the latest block number
        latest_block = web3.eth.block_number

        # Iterate over new blocks since the last check
        for block_number in range(self.previous_block + 1, latest_block + 1):
            block = web3.eth.getBlock(block_number, full_transactions=True)
            for tx in block.transactions:
                # Analyze the transaction trace
                self.analyze_transaction(tx.hash)
        # Update the previous block number
        self.previous_block = latest_block

    
    def analyze_transaction(self, tx_hash):
        try:
            trace = web3.manager.request_blocking('debug_traceTransaction', [
                tx_hash.hex(),
                {'tracer': 'callTracer'}
            ])

            # Recursively convert the trace from AttributeDict to regular dictionaries
            trace = convert_attribute_dict(trace)

            # # Save the trace to a JSON file
            # with open(f"trace_{tx_hash.hex()}.json", "w") as f:
            #     json.dump(trace, f, indent=4)
            
            call_count = 0
            for log in trace.get('structLogs', []):
                call_count += self.count_withdraw_calls(log)

            # print(f"Count CALL to contract: {call_count}")

            if call_count > 1:
                print(f"Reentrancy attack detected in transaction {tx_hash.hex()}! withdraw() called {call_count} times.")
            else:
                print(f"No reentrancy detected in transaction {tx_hash.hex()}. withdraw() called {call_count} time(s).")
        except Exception as e:
            print(f"Failed to get trace for transaction {tx_hash.hex()}: {e}")



    def count_withdraw_calls(self, log):
        call_count = 0
        stack = log.get('stack', [])
        op = log.get('op', '')
        depth = log.get('depth', 0)

        # Check for a CALL operation and extract the to_address
        if op in ['CALL', 'DELEGATECALL', 'CALLCODE', 'STATICCALL']:
            if len(stack) >= 2:  # Ensure there are at least two items in the stack
                to_address = '0x' + stack[-2][-40:].lower()  # Extract the last 40 characters and add '0x' prefix
                contract_address = self.vulnerable_contract.address.lower()

                if to_address == contract_address:
                    # Iterate through the stack to find the function selector
                    for i in range(len(stack) - 1):
                         if stack[i].endswith(self.withdraw_function_selector()[-8:]):  # Check if it ends with the function selector
                            # The next item in the stack is the input data
                            #input_data = stack[-1]
                            
                            # Convert the input data from hex to decimal
                            #input_data_decimal = int(input_data, 16)  # Convert hex to decimal
                            
                            #print("Detected withdraw() function call.")
                            # print(f"Detected withdraw() function call. Input data (decimal): {input_data_decimal}")
                            call_count += 1
                            
                            # # Verify if this is the withdraw function call
                            # if input_data.startswith(self.withdraw_function_selector()):
                            #     print("Detected withdraw() function call.")
                            #     call_count += 1
                            # break  # Exit loop after finding the function selector

        return call_count

    def withdraw_function_selector(self):
        # Get the function selector for withdraw()
        function_signature = 'withdraw(uint256)'
        selector = web3.keccak(text=function_signature)[:4]
        selector_hex = '0x' + selector.hex()
        return selector_hex



# Load deployed contracts
with open('deployed_contracts.json') as f:
    deployed_addresses = json.load(f)

vulnerable_contract = load_contract('VulnerableContract', deployed_addresses['VulnerableContract'])
attacker_contract = load_contract('Attacker', deployed_addresses['Attacker'])

# Create the detector instance
detector = ReentrancyDetector(vulnerable_contract)

def check_and_deposit_funds(contract, required_balance_eth):
    balance = web3.eth.get_balance(contract.address)
    balance_in_ether = web3.fromWei(balance, 'ether')

    print(f"Vulnerable contract current balance: {balance_in_ether} ETH")

    if balance_in_ether < required_balance_eth:
        deposit_amount = required_balance_eth - float(balance_in_ether)
        print(f"Depositing {deposit_amount} Ether to the vulnerable contract.")
        tx_hash = contract.functions.deposit().transact({
            'from': web3.eth.accounts[0], 'value': web3.toWei(deposit_amount, 'ether')
        })
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print("Deposit complete, vulnerable contract balance replenished.")

def simulate_targeted_attack(amount_ether, target_drain_ether):
    print(f"Simulating attack with {amount_ether} ETH, targeting to drain {target_drain_ether} ETH")

    attacker_balance = web3.eth.get_balance(web3.eth.accounts[1])
    required_amount = web3.toWei(amount_ether, 'ether')
    target_drain_amount = web3.toWei(target_drain_ether, 'ether')

    if attacker_balance < required_amount:
        print("Attacker does not have enough Ether to perform the attack.")
        return

    # Set the gas limit to a value that is high but within the block limit
    gas_limit = 3000000  # Adjust this to be within your block's gas limit

    # Attacker initiates the attack with target drain amount
    tx_hash = attacker_contract.functions.attack(target_drain_amount).transact({
        'from': web3.eth.accounts[1],
        'value': required_amount,
        'gas': gas_limit
    })
    web3.eth.wait_for_transaction_receipt(tx_hash)
    print("Attack transaction mined.")
    
    # Print balances after the attack
    vulnerable_balance = web3.eth.get_balance(vulnerable_contract.address)
    attacker_balance = web3.eth.get_balance(web3.eth.accounts[1])
    
    print(f"Vulnerable contract balance: {web3.fromWei(vulnerable_balance, 'ether')} ETH")
    print(f"Attacker's balance: {web3.fromWei(attacker_balance, 'ether')} ETH")


def fund_attacker_account():
    # Transfer Ether from account[0] to account[1] if needed
    attacker_balance = web3.eth.get_balance(web3.eth.accounts[1])
    if attacker_balance < web3.toWei(1, 'ether'):
        tx_hash = web3.eth.send_transaction({
            'from': web3.eth.accounts[0],
            'to': web3.eth.accounts[1],
            'value': web3.toWei(5, 'ether')  # Transfer 5 ETH
        })
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print("Transferred 5 ETH to attacker account.")

def print_attacker_eth_balance():
    balance = web3.eth.get_balance(web3.eth.accounts[1])
    balance_in_ether = web3.fromWei(balance, 'ether')
    print(f"Attacker's Ether balance: {balance_in_ether} ETH")

def print_vulnerable_contract_balance():
    balance = web3.eth.get_balance(vulnerable_contract.address)
    balance_in_ether = web3.fromWei(balance, 'ether')
    print(f"Vulnerable contract Ether balance: {balance_in_ether} ETH")

def run_detection_cycle():
    detector.detect_reentrancy()


def test_vulnerable_contract():
    print("Depositing 1 ETH to the vulnerable contract.")
    tx_hash = vulnerable_contract.functions.deposit().transact({
        'from': web3.eth.accounts[0],
        'value': web3.toWei(1, 'ether')
    })
    web3.eth.wait_for_transaction_receipt(tx_hash)
    print("Deposit complete.")

    print("Withdrawing 0.5 ETH from the vulnerable contract.")
    tx_hash = vulnerable_contract.functions.withdraw(web3.toWei(0.5, 'ether')).transact({
        'from': web3.eth.accounts[0],
        'gas': 300000
    })
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Withdrawal complete: {receipt}")


def simulate_attack():
    print("Simulating attack with 0.05 ETH, targeting to drain 0.1 ETH")
    
    # Start the attack with smaller values
    tx_hash = attacker_contract.functions.attack(web3.toWei(0.1, 'ether')).transact({
        'from': web3.eth.accounts[1],
        'value': web3.toWei(0.05, 'ether'),
        'gas': 3000000  # Provide ample gas for the reentrancy attack
    })
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Attack transaction mined: {receipt}")
    
    # Print balances after the attack
    vulnerable_balance = web3.eth.get_balance(vulnerable_contract.address)
    attacker_balance = web3.eth.get_balance(web3.eth.accounts[1])
    
    print(f"Vulnerable contract balance: {web3.fromWei(vulnerable_balance, 'ether')} ETH")
    print(f"Attacker's balance: {web3.fromWei(attacker_balance, 'ether')} ETH")



# check_and_deposit_funds(attacker_contract, 1)
check_and_deposit_funds(vulnerable_contract, 0.1)
simulate_targeted_attack(0.01, 0.05)  # Simulate an attack with 0.1 Ether, targeting to drain 0.5 Ether
run_detection_cycle()  # Run detection after the attack
for i in range(5):
    check_and_deposit_funds(vulnerable_contract, 0.1)
    simulate_targeted_attack(0.01, 0.1)  # Simulate small attacks
    run_detection_cycle()  # Run detection after each attack

#test_vulnerable_contract()