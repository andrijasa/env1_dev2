import time
import gymnasium as gym
from gymnasium import spaces
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from stable_baselines3.common.env_util import make_vec_env
from web3 import Web3, middleware
from web3.middleware import geth_poa_middleware
import json
import os
from web3.datastructures import AttributeDict
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import EvalCallback, StopTrainingOnRewardThreshold
from stable_baselines3.common.logger import configure
from stable_baselines3.common.callbacks import BaseCallback
import os
import torch
print(torch.cuda.is_available())
print(torch.cuda.current_device())
print(torch.cuda.get_device_name(torch.cuda.current_device()))


# Simulating Smart Contract and Ganache Blockchain Environment
ganache_url = "http://127.0.0.1:7545"
CONTRACTS_PATH = "./build/contracts"
web3 = Web3(Web3.HTTPProvider(ganache_url))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)

# Define the TensorBoard log directory
log_dir = "./ppo_tensorboard/"
os.makedirs(log_dir, exist_ok=True)


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
            #print(f"Intercepted transaction: {tx}")
            if risk_score(tx):
                print("Transaction blocked due to high risk")
                return {"error": "Transaction blocked by middleware"}
        return make_request(method, params)
    return middleware_fn

# Inject middleware into Web3
#web3.middleware_onion.add(transaction_middleware)

def check_and_deposit_funds(contract, required_balance_eth):
    balance = web3.eth.get_balance(contract.address)
    balance_in_ether = web3.fromWei(balance, 'ether')

    #print(f"Vulnerable contract current balance: {balance_in_ether} ETH")

    if balance_in_ether < required_balance_eth:
        deposit_amount = required_balance_eth - float(balance_in_ether)
        print(f"Depositing {deposit_amount} Ether to the vulnerable contract.")
        tx_hash = contract.functions.deposit().transact({
            'from': web3.eth.accounts[0], 'value': web3.toWei(deposit_amount, 'ether')
        })
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print("Deposit complete, vulnerable contract balance replenished.")

def run_detection_cycle():
    return detector.detect_reentrancy()

# Custom Environment for Reinforcement Learning
class ReentrancyEnv(gym.Env):
    metadata = {'render_modes': ['human', 'rgb_array']}

    def __init__(self, render_mode=None):
        super(ReentrancyEnv, self).__init__()
        self.action_space = spaces.Discrete(2)  # Block or Allow transaction
        
        # Define maximum expected values for normalization
        self.max_balance = 100.0  # Example: Assume 100 Ether is the maximum expected balance
        self.max_funds_drained = 1.0  # Example: Assume 1 Ether is the maximum amount to be drained
        self.max_gas = 500000  # Example maximum gas limit
        self.max_time = 60  # Example: 60 seconds as maximum time since last transaction
        
        # Extended observation space: [normalized balance, call count, normalized funds drained, normalized gas used, normalized sender balance, normalized time since last tx, call depth]
        self.observation_space = spaces.Box(low=0, high=1, shape=(7,), dtype=np.float32)
        
        self.vulnerable_contract = vulnerable_contract
        self.attacker_contract = attacker_contract
        self.attacker_account = attacker_account
        self.detector = ReentrancyDetector(vulnerable_contract)
        self.state = np.zeros(7)  # Initialize with zeros
        self.drained_counter = {}  # Track funds drained by address
        self.attack_threshold = 3  # Number of times funds need to be drained for flagging
        self.max_steps = 100  # Maximum steps per episode
        self.current_step = 0
        self.last_transaction_time = None  # Track time of last transaction
        self.render_mode = render_mode

    def reset(self, seed=None, **kwargs):
        if seed is not None:
            np.random.seed(seed)

        # Reset internal state variables
        self.state = np.zeros(7)  # Reset state to zeros
        self.current_step = 0
        self.last_transaction_time = None  # Reset transaction time

        # Optionally reset balances of smart contracts to initial values
        #self._reset_contract_balances()

        return self.state, {}

    def _reset_contract_balances(self):
        """
        Ensure that both the vulnerable contract and the attacker contract
        have consistent balances at the start of each episode.
        """
        required_vulnerable_balance = 0.001  # Set the initial balance you want for the vulnerable contract
        attacker_starting_balance = 0.01  # Set the initial balance you want for the attacker account

        # Replenish the vulnerable contract's balance if it's below the required amount
        check_and_deposit_funds(self.vulnerable_contract, required_vulnerable_balance)

        # Ensure the attacker's balance is sufficient for performing the attack
        current_attacker_balance = web3.eth.get_balance(self.attacker_account)
        if current_attacker_balance < web3.toWei(attacker_starting_balance, 'ether'):
            difference = web3.toWei(attacker_starting_balance, 'ether') - current_attacker_balance
            tx_hash = web3.eth.send_transaction({
                'from': web3.eth.accounts[0],  # Assuming account 0 is the fund provider
                'to': self.attacker_account,
                'value': difference
            })
            web3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"Attacker's balance replenished to {attacker_starting_balance} ETH")

    def step(self, action):
        reward = 0
        terminated = False
        truncated = False
        funds_drained = 0
        call_count = 0
        call_depth = 0
        gas_used = 0
        current_time = time.time()  # Current time

        if action == 1:  # Allow transaction
            # Simulate the attack and retrieve relevant metrics
            reentrancy_detected, funds_drained, call_count, gas_used, call_depth = self._simulate_attacker()

            if reentrancy_detected:
                # Penalize heavily if a reentrancy attack is detected and funds are drained
                reward = -100 - (10 * call_count)  # Additional penalty based on call count
                if funds_drained > 0:
                    reward -= 50  # Additional penalty if funds are actually drained
            else:
                reward = 5  # Reward for allowing a safe transaction
        else:  # Block transaction
            # Even when blocking, simulate the situation for training consistency
            reentrancy_detected, funds_drained, call_count, gas_used, call_depth = self._simulate_attacker()
            if reentrancy_detected:
                reward = 50  # High reward for correctly blocking a malicious transaction
            else:
                reward = -5  # Penalty for incorrectly blocking a legitimate transaction

        # Update the state with the new observations
        vulnerable_contract_balance = web3.eth.get_balance(self.vulnerable_contract.address)
        normalized_balance = min(float(web3.fromWei(vulnerable_contract_balance, 'ether')) / self.max_balance, 1.0)
        normalized_funds_drained = min(float(web3.fromWei(funds_drained, 'ether')) / self.max_funds_drained, 1.0)
        gas_used_normalized = min(gas_used / self.max_gas, 1.0)
        sender_balance = min(float(web3.fromWei(web3.eth.get_balance(self.attacker_account), 'ether')) / self.max_balance, 1.0)
        time_since_last_tx = min(current_time - (self.last_transaction_time or current_time), self.max_time) / self.max_time
        normalized_call_depth = min(call_depth / 10, 1.0)  # Assuming 10 is the max depth

        # Aggregate the new state
        self.state = np.array([
            normalized_balance,
            call_count,
            normalized_funds_drained,
            gas_used_normalized,
            sender_balance,
            time_since_last_tx,
            normalized_call_depth
        ], dtype=np.float32)
        
        self.current_step += 1
        self.last_transaction_time = current_time  # Update last transaction time

        # Determine if the episode should be terminated
        terminated = self.current_step >= self.max_steps
        truncated = False  # No truncation for now
        info = {}

        # Update the reward with the mean of all rewards in the batch (if running parallel environments)
        if isinstance(reward, np.ndarray):  # If we are running multiple environments
            reward = np.mean(reward)

        # Debugging output (can be removed in production)
        # print(f"Observation: {self.state}")
        # print(f"Action taken: {action}")
        # print(f"Attacker Balance: {web3.fromWei(web3.eth.get_balance(attacker_contract.address), 'ether')} ETH")

        # Rendering for human-readable feedback
        if self.render_mode == 'human':
            self.render()

        # Return the updated state, reward, and done flags
        return self.state, reward, terminated, truncated, info


    def _get_gas_used(self):
        # Retrieve the gas used in the last transaction (this is a placeholder function)
        # In practice, you'd extract this from the transaction receipt
        return 21000  # Example placeholder value

    def render(self, mode='human'):
        if mode == 'human':
            #print(f"Step: {self.current_step}, Balance: {self.state[0]}")
            pass
        elif mode == 'rgb_array':
            pass

    def close(self):
        pass

    def _simulate_attacker(self):
        # check_and_deposit_funds(vulnerable_contract, 0.001)
        # reentrancy_detected, funds_drained, gas_used = simulate_targeted_attack(0.0001, 0.0005)
        # call_count, call_depth = run_detection_cycle()
        # Assign random values to each variable
        # Assign initial random values with specified probabilities

        # reentrancy_detected: True with 30% probability, False with 70% probability
        reentrancy_detected = np.random.choice([True, False], p=[0.3, 0.7])

        # funds_drained: Random value with mean=0.0001 Ether and standard deviation of 0.00005
        # Ensure it's non-negative by taking the absolute value
        funds_drained = abs(np.random.normal(0.0001, 0.00005))

        # call_count: Random integer between 1 and 5, weighted towards lower values
        call_count = np.random.choice(range(1, 6), p=[0.5, 0.3, 0.1, 0.05, 0.05])

        # gas_used: Random value between 21000 and 500000 with higher probability for lower values
        #gas_used = np.random.choice(range(21000, 500001), p=[0.6, 0.01, 49])
        # Generate the range of gas values
        gas_values = range(21000, 500001, 10000)  # 49 values

        # Generate probabilities and normalize them
        probabilities = np.linspace(0.6, 0.01, len(gas_values))
        probabilities /= probabilities.sum()  # Normalize to sum to 1

        # Now select the gas_used with corrected probabilities
        gas_used = np.random.choice(gas_values, p=probabilities)

        # call_depth: Random integer between 1 and 10, with higher probability for lower depths
        #call_depth = np.random.choice(range(1, 13), p=np.linspace(0.4, 0.05, 10))
        call_depth_values = range(1, 13)  # Range with 12 values
        probabilities = np.linspace(0.4, 0.05, len(call_depth_values))  # Adjust to 12 probabilities

        # Normalize the probabilities to sum to 1
        probabilities /= probabilities.sum()

        # Select the call_depth based on the normalized probabilities
        call_depth = np.random.choice(call_depth_values, p=probabilities)
        return reentrancy_detected, funds_drained, call_count, gas_used, call_depth


def simulate_targeted_attack(amount_ether, target_drain_ether):
    print(f"Simulating attack with {amount_ether} ETH, targeting to drain {target_drain_ether} ETH")
    vulnerable_balance_before = web3.eth.get_balance(vulnerable_contract.address)
    attacker_balance = web3.eth.get_balance(web3.eth.accounts[1])
    required_amount = web3.toWei(amount_ether, 'ether')
    target_drain_amount = web3.toWei(target_drain_ether, 'ether')

    if attacker_balance < required_amount:
        print("Attacker does not have enough Ether to perform the attack.")
        return False, 0, 0  # Return false indicating the attack couldn't proceed

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
        vulnerable_balance_after = web3.eth.get_balance(vulnerable_contract.address)
        #attacker_balance_after = web3.eth.get_balance(web3.eth.accounts[1])
        funds_drained = vulnerable_balance_before - vulnerable_balance_after
        receipt = web3.eth.getTransactionReceipt(tx_hash)
        gas_used = receipt.gasUsed  # Retrieve the gas used from the transaction receipt


        return True, funds_drained, gas_used

    except ValueError as e:
        # Handle the case where the transaction was blocked by the middleware
        print(f"Transaction blocked by middleware: {e}")
        return False, 0, 0  # Indicate that the transaction was blocked and no funds were drained

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
        call_count, call_depth = self.analyze_transaction(tx.hash)
        if call_count > 1 or call_depth > 1:
            return call_count, call_depth
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
            max_depth = 0

            for log in trace.get('structLogs', []):
                call_count += self.count_withdraw_calls(log)
                depth = log.get('depth', 0)
                if depth > max_depth:
                    max_depth = depth

            if call_count > 1:
                print(f"Reentrancy attack detected in transaction {tx_hash.hex()}! withdraw() called {call_count} times. Call Depth: {max_depth}")
            
            return call_count, max_depth
            # else:
            #     return 0, 0
        except Exception as e:
            print(f"Failed to get trace for transaction {tx_hash.hex()}: {e}")
            return 0, 0

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
    
# Custom callback to log mean reward
class MeanRewardCallback(BaseCallback):
    def __init__(self, verbose=0):
        super(MeanRewardCallback, self).__init__(verbose)
        self.mean_rewards = []

    def _on_step(self) -> bool:
        # Calculate the mean reward
        mean_reward = np.mean([ep_info['r'] for ep_info in self.locals['infos'] if 'r' in ep_info])
        self.mean_rewards.append(mean_reward)
        
        if self.verbose > 0 and self.n_calls % 5 == 0:
            print(f"Mean Reward after {self.n_calls} steps: {mean_reward}")
        
        return True

class PrintTimestepCallback(BaseCallback):
    def __init__(self, verbose=0):
        super(PrintTimestepCallback, self).__init__(verbose)
        self.start_time = None
        self.episode_start_time = None
        self.episode_num = 0
        self.episode_rewards = []

    def _on_training_start(self) -> None:
        self.start_time = time.time()

    def _on_step(self) -> bool:
        # Initialize episode start time if not set
        if self.episode_start_time is None:
            self.episode_start_time = time.time()

        # Collect reward and timestep information
        reward = self.locals['rewards'][0]  # Assuming single environment
        self.episode_rewards.append(reward)

        # Check if episode is done
        if self.locals['dones'][0]:  # If the first environment is done
            self.episode_num += 1

            # Calculate mean reward
            mean_reward = sum(self.episode_rewards) / len(self.episode_rewards)
            
            # Calculate episode duration
            episode_end_time = time.time()
            episode_duration = episode_end_time - self.episode_start_time
            formatted_episode_duration = time.strftime("%H:%M:%S", time.gmtime(episode_duration))

            # Calculate total elapsed time since training started
            elapsed_time = episode_end_time - self.start_time
            formatted_total_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))

            # Print the information
            print(f"Total Time: {formatted_total_time} | Episode Duration: {formatted_episode_duration} | Timestep: {self.num_timesteps} | Episode: {self.episode_num} | Mean Reward: {mean_reward:.2f}")
            
            # Reset episode-specific variables
            self.episode_rewards = []  # Reset rewards for the next episode
            self.episode_start_time = None  # Reset the start time for the next episode

        return True  # Returning True to continue training

# Initialize the detector
detector = ReentrancyDetector(vulnerable_contract)

# Initialize the environment
#env = DummyVecEnv([lambda: ReentrancyEnv(vulnerable_contract, attacker_contract, attacker_account, detector)])
#env = make_vec_env(lambda: ReentrancyEnv(render_mode='human'), n_envs=4)
env = make_vec_env(lambda: ReentrancyEnv(render_mode='human'), n_envs=1)

# Create the PPO model with TensorBoard logging enabled
model = PPO("MlpPolicy", env, verbose=1, tensorboard_log=log_dir, device='cuda')


# Optionally, configure the logger to log additional metrics
new_logger = configure(log_dir, ["stdout", "csv", "tensorboard"])
model.set_logger(new_logger)

# Instantiate the callback
Print_Timestep_Callback = PrintTimestepCallback()

# Train the model with the custom callback
model.learn(total_timesteps=5000, callback=Print_Timestep_Callback)

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
