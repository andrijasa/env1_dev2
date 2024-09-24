import gymnasium as gym
from gymnasium import spaces
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from web3 import Web3, middleware
from web3.middleware import geth_poa_middleware
import json
import os
from web3.datastructures import AttributeDict

# Simulating Smart Contract and Ganache Blockchain Environment
ganache_url = "http://127.0.0.1:7545"
CONTRACTS_PATH = "./build/contracts"
web3 = Web3(Web3.HTTPProvider(ganache_url))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)

# Helper function to load contract ABIs and addresses
def load_contracts(path, deployed_addresses):
    contracts = {}
    for filename in os.listdir(path):
        if filename.endswith(".json"):
            with open(os.path.join(path, filename)) as f:
                contract_data = json.load(f)
                contract_name = filename.split(".")[0]
                if contract_name in deployed_addresses:
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

attacker_account = web3.eth.accounts[1]  # Example attacker account

# Risk Scoring System
def risk_score(transaction):
    # Basic risk checks (can be expanded with more sophisticated methods)
    if transaction['to'] in malicious_addresses: #or int(transaction['gas'],16) > 200000:
        return True  # Suspicious transaction

    # check_and_deposit_funds(vulnerable_contract, 0.001)
    # reentrancy_detected, funds_drained = simulate_targeted_attack(0.0001, 0.0005)
    # call_count = run_detection_cycle()
    return False

malicious_addresses = set(['0x5b717f4078f788eCC3B0602b28810Ea1bB780168', '0xMaliciousAddress2'])

# Web3 Middleware for transaction interception
def transaction_middleware(make_request, web3):
    def middleware_fn(method, params):
        if method == "eth_sendTransaction":
            tx = params[0]
            print(f"Intercepted transaction: {tx}")
            if risk_score(tx):
                print("Transaction blocked due to high risk")
                return {"error": "Transaction blocked by middleware"}
        return make_request(method, params)
    return middleware_fn

# Inject middleware into Web3
web3.middleware_onion.add(transaction_middleware)

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

def run_detection_cycle():
    detector.detect_reentrancy()

# Custom Environment for Reinforcement Learning
class ReentrancyEnv(gym.Env):
    def __init__(self, vulnerable_contract, attacker_contract, attacker_account, detector):
        super(ReentrancyEnv, self).__init__()
        self.action_space = spaces.Discrete(2)  # Block or Allow transaction
        self.observation_space = spaces.Box(low=0, high=1, shape=(3,), dtype=np.float32)
        self.vulnerable_contract = vulnerable_contract
        self.attacker_contract = attacker_contract
        self.attacker_account = attacker_account
        self.detector = ReentrancyDetector(vulnerable_contract)
        self.state = [0, 0, 0]  # Example observation: [gas, sender_balance, is_malicious]
        self.drained_counter = {}  # Track funds drained by address
        self.attack_threshold = 3  # Number of times funds need to be drained for flagging

    def reset(self, seed=None, **kwargs):
        if seed is not None:
            np.random.seed(seed)
        self.state = np.random.random(3)
        return self.state, {}

    def step(self, action):
        reward = 0
        terminated = False
        truncated = False
        funds_drained = 0
        call_count = 0

        if action == 1:  # Allow transaction
            reentrancy_detected, funds_drained, call_count = self._simulate_attacker()

            if reentrancy_detected:
                # Penalize based on the number of calls detected
                reward = -10 * call_count  # Increase the penalty with the number of calls
                if funds_drained > 0:
                    reward -= 20  # Additional penalty if funds are actually drained
            else:
                reward = 1  # Small reward for allowing a safe transaction
        else:
            reward = 10  # Reward for blocking a transaction

        terminated = np.random.random() > 0.95
        truncated = False

        return self.state, reward, terminated, truncated, {'funds_drained': funds_drained, 'call_count': call_count}
    
    def _simulate_attacker(self):
        check_and_deposit_funds(vulnerable_contract, 0.001)
        reentrancy_detected, funds_drained = simulate_targeted_attack(0.0001, 0.0005)
        call_count = run_detection_cycle()
        return reentrancy_detected, funds_drained, call_count

def simulate_targeted_attack(amount_ether, target_drain_ether):
    print(f"Simulating attack with {amount_ether} ETH, targeting to drain {target_drain_ether} ETH")

    attacker_balance = web3.eth.get_balance(web3.eth.accounts[1])
    required_amount = web3.toWei(amount_ether, 'ether')
    target_drain_amount = web3.toWei(target_drain_ether, 'ether')

    if attacker_balance < required_amount:
        print("Attacker does not have enough Ether to perform the attack.")
        return False, 0  # Return false indicating the attack couldn't proceed

    gas_limit = 3000000  # Set the gas limit

    try:
        tx_hash = attacker_contract.functions.attack(target_drain_amount).transact({
            'from': web3.eth.accounts[1],
            'value': required_amount,
            'gas': gas_limit
        })
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print("Attack transaction mined.")

        # Check balances after the attack
        vulnerable_balance = web3.eth.get_balance(vulnerable_contract.address)
        funds_drained = web3.fromWei(web3.eth.get_balance(web3.eth.accounts[1]) - attacker_balance, 'ether')

        return True, funds_drained

    except ValueError as e:
        # Handle the case where the transaction was blocked by the middleware
        print(f"Transaction blocked by middleware: {e}")
        return False, 0  # Indicate that the transaction was blocked and no funds were drained

# Reentrancy Detector class from previous code
class ReentrancyDetector:
    def __init__(self, vulnerable_contract):
        self.vulnerable_contract = vulnerable_contract
        self.previous_block = web3.eth.block_number

    def detect_reentrancy(self):
        latest_block = web3.eth.block_number
        # for block_number in range(self.previous_block + 1, latest_block + 1):
        #     block = web3.eth.getBlock(block_number, full_transactions=True)
        #     for tx in block.transactions:
        #         print(f"call_count:{self.analyze_transaction(tx.hash)}")
        #self.previous_block = latest_block
        block = web3.eth.getBlock(latest_block, full_transactions=True)
        tx = block.transactions[-1]
        call_count = self.analyze_transaction(tx.hash)
        if call_count > 1:
            return call_count
        else:
            return 0
        

    # return reentrancy_detected, web3.fromWei(balance_before - balance_after, 'ether')

    def analyze_transaction(self, tx_hash):
        try:
            trace = web3.manager.request_blocking('debug_traceTransaction', [
                tx_hash.hex(),
                {'tracer': 'callTracer'}
            ])
            trace = convert_attribute_dict(trace)
            call_count = 0
            for log in trace.get('structLogs', []):
                call_count += self.count_withdraw_calls(log)
            if call_count > 1:
                print(f"Reentrancy attack detected in transaction {tx_hash.hex()}! withdraw() called {call_count} times.")
                return call_count
            else:
                return 0
        except Exception as e:
            print(f"Failed to get trace for transaction {tx_hash.hex()}: {e}")

    def count_withdraw_calls(self, log):
        call_count = 0
        stack = log.get('stack', [])
        op = log.get('op', '')

        if op in ['CALL', 'DELEGATECALL', 'CALLCODE', 'STATICCALL']:
            if len(stack) >= 2:
                to_address = '0x' + stack[-2][-40:].lower()
                contract_address = self.vulnerable_contract.address.lower()

                if to_address == contract_address:
                    for i in range(len(stack) - 1):
                        if stack[i].endswith(self.withdraw_function_selector()[-8:]):
                            call_count += 1
        return call_count

    def withdraw_function_selector(self):
        function_signature = 'withdraw(uint256)'
        selector = web3.keccak(text=function_signature)[:4]
        selector_hex = '0x' + selector.hex()
        return selector_hex


def convert_attribute_dict(obj):
    if isinstance(obj, AttributeDict):
        return {k: convert_attribute_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_attribute_dict(i) for i in obj]
    else:
        return obj

# Define the Attacker class
class AttackerAgent:
    def __init__(self, max_tx=1000):
        self.tx_count = 0
        self.max_tx = max_tx  # Limit on the number of transactions

    def attack(self):
        if self.tx_count >= self.max_tx:
            print(f"Attacker has reached max transactions ({self.max_tx})")
            return None  # Stop sending transactions
        print(f"Attacker sending malicious transaction {self.tx_count}")
        self.tx_count += 1
        return {'to': '0xMaliciousAddress1', 'gas': 60000}

# Initialize the detector
detector = ReentrancyDetector(vulnerable_contract)

# Initialize the environment
env = DummyVecEnv([lambda: ReentrancyEnv(vulnerable_contract, attacker_contract, attacker_account, detector)])

# PPO Training for Defender Agent
model = PPO("MlpPolicy", env, verbose=1)
model.learn(total_timesteps=10000)

# Save the trained model
model.save("ppo_defender")

# Load the trained model for testing
model = PPO.load("ppo_defender")

# Testing phase: Intercepting transactions
obs = env.reset()
for episode in range(10):
    done = False
    total_reward = 0
    
    attacker = AttackerAgent(max_tx=100)
    
    while not done:
        action, _states = model.predict(obs)
        
        tx = attacker.attack()
        if tx is None:
            break
        
        obs, reward, done, info = env.step([action])
        total_reward += reward
    
    print(f"Episode {episode + 1}: Total Reward: {total_reward}")
    obs = env.reset()

# # Middleware for intercepting and analyzing transactions using the trained model
# def trained_model_middleware(make_request, web3):
#     def middleware_fn(method, params):
#         if method == "eth_sendTransaction":
#             tx = params[0]
#             gas_value = int(tx['gas'], 16) if '0x' in tx['gas'] else int(tx['gas'])
#             sender_balance = web3.eth.get_balance(tx['from'])
#             obs = [gas_value / 100000, sender_balance / 1e18, tx['to'] in malicious_addresses]
#             obs = [obs]
#             action, _states = model.predict(obs)

#             if action == 0:
#                 print("Transaction blocked by trained model")
#                 return {"error": "Transaction blocked by model"}
#         return make_request(method, params)
#     return middleware_fn

# web3.middleware_onion.add(trained_model_middleware)
