import gymnasium as gym
from gymnasium import spaces  # Add this import
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from web3 import Web3, middleware
from web3.middleware import geth_poa_middleware
import json
import os

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

attacker_account = web3.eth.accounts[1]  # Example attacker account

# Risk Scoring System
def risk_score(transaction):
    # Basic risk checks (can be expanded with more sophisticated methods)
    if transaction['to'] in malicious_addresses or int(transaction['gas'],16) > 200000:
        return True  # Suspicious transaction
    return False

malicious_addresses = set(['', '0xMaliciousAddress2'])

# Web3 Middleware for transaction interception
def transaction_middleware(make_request, web3):
    def middleware_fn(method, params):
        if method == "eth_sendTransaction":
            tx = params[0]
            if risk_score(tx):
                print("Transaction blocked due to high risk")
                return {"error": "Transaction blocked by middleware"}
        return make_request(method, params)
    return middleware_fn

# Inject middleware into Web3
web3.middleware_onion.add(transaction_middleware)

# Custom Environment for Reinforcement Learning
class ReentrancyEnv(gym.Env):
    def __init__(self, vulnerable_contract, attacker_contract, attacker_account):
        super(ReentrancyEnv, self).__init__()
        self.action_space = spaces.Discrete(2)  # Block or Allow transaction
        self.observation_space = spaces.Box(low=0, high=1, shape=(3,), dtype=np.float32)
        self.vulnerable_contract = vulnerable_contract
        self.attacker_contract = attacker_contract
        self.attacker_account = attacker_account
        self.state = [0, 0, 0]  # Example observation: [gas, sender_balance, is_malicious]
        self.drained_counter = {}  # Track funds drained by address
        self.attack_threshold = 3  # Number of times funds need to be drained for flagging

    def reset(self, seed=None, **kwargs):
        if seed is not None:
            np.random.seed(seed)
        # Reset the environment and state
        self.state = np.random.random(3)
        return self.state, {}  # Return state and an empty info dictionary

    def step(self, action):
        reward = 0
        terminated = False
        truncated = False
        funds_drained = 0  # Initialize funds_drained to avoid UnboundLocalError

        # If action is 1 (Allow transaction), simulate an attacker
        if action == 1:
            reentrancy_detected, funds_drained = self._simulate_attacker()

            attacker_address = web3.eth.accounts[1]  # Example attacker address

            if reentrancy_detected:
                if attacker_address not in self.drained_counter:
                    self.drained_counter[attacker_address] = 0

                self.drained_counter[attacker_address] += 1

                if self.drained_counter[attacker_address] >= self.attack_threshold:
                    print(f"Reentrancy attack detected from {attacker_address}! Flagging address.")
                    reward = -20  # Major penalty for allowing repeated attacks
                    self.drained_counter[attacker_address] = 0  # Reset counter
                else:
                    reward = -10  # Penalty for allowing a reentrancy attack
            else:
                reward = 1  # Small reward for allowing a safe transaction

        else:
            reward = 10  # Reward for blocking any suspicious transaction

        # Set the termination or truncation condition
        terminated = np.random.random() > 0.95  # End the episode randomly for now
        truncated = False  # Set to True if you want to use a time limit for episode truncation

        # Return the new state, reward, terminated, truncated, and funds drained information
        return self.state, reward, terminated, truncated, {'funds_drained': funds_drained}

    def _simulate_attacker(self):
        # Simulate the reentrancy attack, this returns whether an attack happened and the funds drained
        return _simulate_attacker(self.vulnerable_contract, self.attacker_contract, self.attacker_account)



def _simulate_attacker(vulnerable_contract, attacker_contract, attacker_account):
    # # Check balances before the attack
    balance_before = web3.eth.get_balance(vulnerable_contract.address)
    balance_attack_before = web3.eth.get_balance(attacker_contract.address)
    # print(f"Type of balance_before: {type(balance_before)}")
    print(f"Vulnerable contract balance before attack: {web3.fromWei(balance_before, 'gwei')} gwei")
    print(f"Vulnerable Attacker balance before attack: {web3.fromWei(balance_attack_before, 'gwei')} gwei")

    reentrancy_detected = False  # Initialize the flag for reentrancy detection

    ether_in_wei = web3.toWei(1, 'ether')
    # Ensure both values are integers
    if isinstance(ether_in_wei, str):
        ether_in_wei = int(ether_in_wei)
    
    if balance_before >= ether_in_wei:
        try:
            # Debug print before transaction
            print(f"Attempting reentrancy attack with {web3.toWei(100000, 'gwei')} wei")
            
                # Ensure all values are integers
            tx_value = int(web3.toWei(100000, 'gwei'))  # Ensure integer
            tx_gas = 200000  # Ensure integer
            tx_gas_price = int(web3.toWei('1', 'gwei'))  # Ensure integer
            
            # Execute the attack
            tx_hash = attacker_contract.functions.attack().transact({
                'from': attacker_account,
                'value': tx_value,
                'gas': tx_gas,
                'gasPrice': tx_gas_price
            })
            web3.eth.wait_for_transaction_receipt(tx_hash)
            print("Reentrancy attack attempted!")
        except Exception as e:
            print(f"Attack failed: {e}")

    else:
        print("Insufficient balance for the attack.")

    # Check balances after the attack
    balance_after = web3.eth.get_balance(vulnerable_contract.address)
    balance_attacker_after = web3.eth.get_balance(attacker_contract.address)
    
    # print(f"Type of balance_after: {type(balance_after)}")
    print(f"Vulnerable contract balance after attack: {web3.fromWei(balance_after, 'gwei')} gwei")
    print(f"Vulnerable attacker balance after attack: {web3.fromWei(balance_attacker_after, 'gwei')} gwei")

    # Compare the balance before and after the attack
    if balance_after < balance_before:
        print("Reentrancy attack detected! Funds were drained.")
        reentrancy_detected = True  # Set flag to True if funds were drained
    else:
        print("No reentrancy attack detected. No funds drained.")

    return reentrancy_detected, web3.fromWei(balance_before - balance_after, 'ether')



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


# Initialize the environment
env = DummyVecEnv([lambda: ReentrancyEnv(vulnerable_contract, attacker_contract, attacker_account)])

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
    
    # Reset the attacker for each episode if necessary
    attacker = AttackerAgent(max_tx=100)  # Reset attacker behavior if needed
    
    while not done:
        # Defender agent predicts an action based on current observation
        action, _states = model.predict(obs)
        
        # Attacker sends a transaction
        tx = attacker.attack()
        
        # If attacker stops sending transactions, exit the loop
        if tx is None:
            print("No more transactions to intercept.")
            break
        
        # Evaluate the transaction risk and possibly override the action
        if risk_score(tx):
            action = 0  # Block the transaction as suspicious
        
        # Take the action in the environment and gather the results
        obs, reward, done, info = env.step([action])  # Wrap action in a list
        
        # Accumulate rewards for this episode
        total_reward += reward
    
    # Output the total reward at the end of the episode
    print(f"Episode {episode + 1}: Total Reward: {total_reward}")

    # Reset environment for the next episode
    obs = env.reset()


# Middleware for intercepting and analyzing transactions using the trained model
def trained_model_middleware(make_request, web3):
    def middleware_fn(method, params):
        if method == "eth_sendTransaction":
            tx = params[0]

            # Convert gas to integer, handle both hex and decimal formats
            gas_value = int(tx['gas'], 16) if '0x' in tx['gas'] else int(tx['gas'])  # Check if gas is in hex format
            sender_balance = web3.eth.get_balance(tx['from'])  # Sender balance (Wei)

            # Extract features from the transaction for the model
            obs = [gas_value / 100000, sender_balance / 1e18, tx['to'] in malicious_addresses]
            
            # Convert the transaction details into an observation for the model
            obs = [obs]
            
            # Use the trained model to predict whether to block or allow
            action, _states = model.predict(obs)

            if action == 0:  # Block the transaction if the model predicts so
                print("Transaction blocked by trained model")
                return {"error": "Transaction blocked by model"}
            
        # If not blocking, pass the request through
        return make_request(method, params)
    
    return middleware_fn

# Add trained model middleware to Web3
web3.middleware_onion.add(trained_model_middleware)

