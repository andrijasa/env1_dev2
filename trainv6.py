import time
import os
import numpy as np
import gymnasium as gym
from gymnasium import spaces
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.logger import configure
from stable_baselines3.common.callbacks import BaseCallback
import torch
from web3 import Web3
from web3.middleware import geth_poa_middleware
import json
from sacred import Experiment
from sacred.observers import FileStorageObserver, MongoObserver
import optuna

# Initialize Sacred Experiment
ex = Experiment("reentrancy_rl")

# Add observers
ex.observers.append(FileStorageObserver('./sacred_logs'))
ex.observers.append(MongoObserver(url='mongodb://localhost:27017', db_name='env1_dev2'))

# Device selection
def check_device(use_gpu=True):
    if use_gpu and torch.cuda.is_available():
        device = torch.device("cuda")
        print("CUDA Available:", True)
        print("Current CUDA Device:", torch.cuda.current_device())
        print("Device Name:", torch.cuda.get_device_name(torch.cuda.current_device()))
    else:
        device = torch.device("cpu")
        if use_gpu and not torch.cuda.is_available():
            print("CUDA is not available. Falling back to CPU.")
        else:
            print("Using CPU.")
    return device

# Web3 setup
def setup_web3(ganache_url):
    web3 = Web3(Web3.HTTPProvider(ganache_url))
    web3.middleware_onion.inject(geth_poa_middleware, layer=0)
    return web3

# Load contracts
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

# Risk scoring (not changed)
def risk_score(transaction, malicious_addresses):
    if transaction['to'] in malicious_addresses:
        return True
    return False

# Deposit funds if needed
def check_and_deposit_funds(contract, required_balance_eth, web3):
    balance = web3.eth.get_balance(contract.address)
    balance_in_ether = web3.fromWei(balance, 'ether')

    if balance_in_ether < required_balance_eth:
        deposit_amount = required_balance_eth - float(balance_in_ether)
        print(f"Depositing {deposit_amount} Ether to the vulnerable contract.")
        tx_hash = contract.functions.deposit().transact({
            'from': web3.eth.accounts[0], 'value': web3.toWei(deposit_amount, 'ether')
        })
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print("Deposit complete, vulnerable contract balance replenished.")

# Attack simulation (not changed)
def simulate_targeted_attack(amount_ether, target_drain_ether, vulnerable_contract, attacker_contract, web3):
    print(f"Simulating attack with {amount_ether} ETH, targeting to drain {target_drain_ether} ETH")
    vulnerable_balance_before = web3.eth.get_balance(vulnerable_contract.address)
    attacker_balance = web3.eth.get_balance(web3.eth.accounts[1])
    required_amount = web3.toWei(amount_ether, 'ether')
    target_drain_amount = web3.toWei(target_drain_ether, 'ether')

    if attacker_balance < required_amount:
        print("Attacker does not have enough Ether to perform the attack.")
        return False, 0, 0

    gas_limit = 3000000

    try:
        tx_hash = attacker_contract.functions.attack(target_drain_amount).transact({
            'from': web3.eth.accounts[1],
            'value': required_amount,
            'gas': gas_limit
        })
        web3.eth.wait_for_transaction_receipt(tx_hash)
        print("Attack transaction mined.")

        vulnerable_balance_after = web3.eth.get_balance(vulnerable_contract.address)
        funds_drained = vulnerable_balance_before - vulnerable_balance_after
        receipt = web3.eth.getTransactionReceipt(tx_hash)
        gas_used = receipt.gasUsed

        return True, funds_drained, gas_used

    except ValueError as e:
        print(f"Transaction blocked by middleware: {e}")
        return False, 0, 0

# Reentrancy detection (not changed)
class ReentrancyDetector:
    def __init__(self, vulnerable_contract, web3):
        self.vulnerable_contract = vulnerable_contract
        self.previous_block = web3.eth.block_number
        self.web3 = web3

    def detect_reentrancy(self):
        latest_block = self.web3.eth.block_number
        block = self.web3.eth.getBlock(latest_block, full_transactions=True)
        tx = block.transactions[-1]
        call_count, call_depth = self.analyze_transaction(tx.hash)
        return call_count, call_depth if call_count > 1 or call_depth > 1 else 0, 0

    def analyze_transaction(self, tx_hash):
        try:
            trace = self.web3.manager.request_blocking('debug_traceTransaction', [
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
        selector = self.web3.keccak(text=function_signature)[:4]
        selector_hex = '0x' + selector.hex()
        return selector_hex

# Convert Web3 results (not changed)
def convert_attribute_dict(obj):
    if isinstance(obj, dict):
        return {k: convert_attribute_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_attribute_dict(i) for i in obj]
    else:
        return obj

# Custom environment (not changed)
class ReentrancyEnv(gym.Env):
    metadata = {'render_modes': ['human', 'rgb_array']}

    def __init__(self, hyperparameters, vulnerable_contract, attacker_contract, attacker_account, detector, web3, render_mode=None):
        super(ReentrancyEnv, self).__init__()
        self.hyperparameters = hyperparameters
        self.action_space = spaces.Discrete(2)
        self.observation_space = spaces.Box(low=0, high=1, shape=(7,), dtype=np.float32)
        self.vulnerable_contract = vulnerable_contract
        self.attacker_contract = attacker_contract
        self.attacker_account = attacker_account
        self.detector = detector
        self.state = np.zeros(7)
        self.drained_counter = {}
        self.attack_threshold = 3
        self.max_steps = self.hyperparameters['max_steps']
        self.current_step = 0
        self.last_transaction_time = None
        self.render_mode = render_mode
        self.web3 = web3

    def reset(self, seed=None, **kwargs):
        if seed is not None:
            np.random.seed(seed)
        self.state = np.zeros(7)
        self.current_step = 0
        self.last_transaction_time = None
        return self.state, {}

    def step(self, action):
        reward, terminated, truncated, funds_drained, call_count, call_depth, gas_used = self._simulate_step(action)
        self._update_state(funds_drained, call_count, gas_used, call_depth)
        self.current_step += 1
        terminated = self.current_step >= self.max_steps
        return self.state, reward, terminated, truncated, {}

    def _simulate_step(self, action):
        reward = 0
        terminated = False
        truncated = False
        funds_drained = 0
        call_count = 0
        call_depth = 0
        gas_used = 0
        current_time = time.time()

        if action == 1:
            reentrancy_detected, funds_drained, call_count, gas_used, call_depth, allowed = self._simulate_attacker()
            reward = self._calculate_reward(reentrancy_detected, funds_drained, call_count, allowed)
        else:
            reentrancy_detected, funds_drained, call_count, gas_used, call_depth, allowed = self._simulate_attacker()
            reward = self._calculate_reward(reentrancy_detected, funds_drained, call_count, allowed)

        self.last_transaction_time = current_time
        return reward, terminated, truncated, funds_drained, call_count, call_depth, gas_used

    def _calculate_reward(self, reentrancy_detected, funds_drained, call_count, allowed):
        reward = -50 if reentrancy_detected else 10  # Penalize heavily if reentrancy is detected
        
        reward -= 25 if funds_drained > 0 else 0  # Penalize for funds drained, with a moderate penalty
        reward -= 5 * call_count if reentrancy_detected else 0  # Penalize for multiple calls in case of an attack
        
        if not allowed and reentrancy_detected:
            reward += 75  # Significant reward for correctly blocking an attack
        
        reward += 20 if not reentrancy_detected and allowed else -10  # Reward for allowing safe transactions
        
        # Apply a maximum and minimum reward cap to avoid excessive penalties or rewards
        reward = max(min(reward, 100), -100)
        
        return reward


    def _simulate_attacker(self):
        # reentrancy_detected = np.random.choice([True, False], p=[0.1, 0.9])
        # funds_drained = abs(np.random.normal(0.0001, 0.00005))
        # call_count = np.random.choice(range(1, 6), p=[0.5, 0.3, 0.1, 0.05, 0.05])
        # gas_values = range(21000, 500001, 10000)
        # gas_used = np.random.choice(gas_values, p=np.linspace(0.6, 0.01, len(gas_values)) / np.sum(np.linspace(0.6, 0.01, len(gas_values))))
        # call_depth_values = range(1, 13)
        # call_depth = np.random.choice(call_depth_values, p=np.linspace(0.4, 0.05, len(call_depth_values)) / np.sum(np.linspace(0.4, 0.05, len(call_depth_values))))
        
        # Use a normal distribution for the amount of funds drained, constrained to positive values
        funds_drained = np.abs(np.random.normal(loc=0.0001, scale=0.00005))  # Mean = 0.0001 Ether, SD = 0.00005 Ether

        # Simulate the number of calls to the vulnerable function using a Poisson distribution (appropriate for count data)
        call_count = np.random.poisson(lam=2)  # Mean number of calls = 2, could be adjusted based on the context

        # Use a uniform distribution for gas used within a realistic range
        gas_used = np.random.uniform(low=21000, high=500000)  # Minimum gas for a transaction is 21000, max is 500000

        # Simulate call depth, potentially indicating recursion, using a geometric distribution
        call_depth = np.random.geometric(p=0.3)  # Higher probability of shallow call depth, tailing off quickly

        # Apply a cutoff to avoid unrealistic extremes
        call_depth = min(call_depth, 10)  # Cap the call depth to a maximum of 10
        call_count = min(call_count, 5)  # Cap the call count to a maximum of 5
        funds_drained = min(funds_drained, 0.001)  # Cap funds drained to 0.001 Ether (for scenario realism)

        # Reentrancy detection: 30% chance of a reentrancy attack being detected (based on scenario)
        reentrancy_detected = np.random.choice([True, False], p=[0.3, 0.7])
        allowed = np.random.choice([True, False], p=[0.3, 0.7])
        return reentrancy_detected, funds_drained, call_count, gas_used, call_depth, allowed

    def _update_state(self, funds_drained, call_count, gas_used, call_depth):
        vulnerable_contract_balance = self.web3.eth.get_balance(self.vulnerable_contract.address)
        normalized_balance = min(float(self.web3.fromWei(vulnerable_contract_balance, 'ether')) / self.hyperparameters['max_balance'], 1.0)
        normalized_funds_drained = min(float(self.web3.fromWei(funds_drained, 'ether')) / self.hyperparameters['max_funds_drained'], 1.0)
        gas_used_normalized = min(gas_used / self.hyperparameters['max_gas'], 1.0)
        sender_balance = min(float(self.web3.fromWei(self.web3.eth.get_balance(self.attacker_account), 'ether')) / self.hyperparameters['max_balance'], 1.0)
        time_since_last_tx = min(time.time() - (self.last_transaction_time or time.time()), self.hyperparameters['max_time']) / self.hyperparameters['max_time']
        normalized_call_depth = min(call_depth / 10, 1.0)

        self.state = np.array([
            normalized_balance,
            call_count,
            normalized_funds_drained,
            gas_used_normalized,
            sender_balance,
            time_since_last_tx,
            normalized_call_depth
        ], dtype=np.float32)

    def render(self, mode='human'):
        if mode == 'human':
            print(f"Step: {self.current_step}, Balance: {self.state[0]}")
        elif mode == 'rgb_array':
            pass

    def close(self):
        pass

# Custom callback for logging and monitoring
class PrintTimestepCallback(BaseCallback):
    def __init__(self, verbose=0, _run=None):
        super(PrintTimestepCallback, self).__init__(verbose)
        self.start_time = None
        self.episode_start_time = None
        self.episode_num = 0
        self.episode_rewards = []
        self.episode_lengths = []
        self.episode_rewards = []
        self.loss_values = []  # Initialize loss_values
        self._run = _run

    def _on_training_start(self) -> None:
        self.start_time = time.time()

    def _on_step(self) -> bool:
        if self.episode_start_time is None:
            self.episode_start_time = time.time()

        reward = self.locals['rewards'][0]
        self.episode_rewards.append(reward)

        loss = self.locals.get('loss')  # Hypothetical: depends on how loss is computed or accessed
        episode_length = self.locals.get('episode_length')
        self.episode_rewards.append(reward)
        if loss is not None:
            self.loss_values.append(loss)
        if episode_length is not None:
            self.episode_lengths.append(episode_length)


        if self.locals['dones'][0]:
            self.episode_num += 1
            mean_reward = np.mean(self.episode_rewards)
            mean_loss = np.mean(self.loss_values) if self.loss_values else None
            mean_episode_length = np.mean(self.episode_lengths) if self.episode_lengths else None

            episode_duration = time.time() - self.episode_start_time
            formatted_episode_duration = time.strftime("%H:%M:%S", time.gmtime(episode_duration))
            elapsed_time = time.time() - self.start_time
            formatted_total_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
            print(f"Total Time: {formatted_total_time} | Episode Duration: {formatted_episode_duration} | Timestep: {self.num_timesteps} | Episode: {self.episode_num} | Mean Reward: {mean_reward:.2f}")
            #self.episode_rewards = []
            #self._run.log_scalar("Episode_Reward", mean_reward, self.episode_num)

            self._run.log_scalar("Timesteps_Reward", mean_reward, self.num_timesteps)
            if mean_loss is not None:
                self._run.log_scalar("Mean_Loss", mean_loss, self.num_timesteps)
            if mean_episode_length is not None:
                self._run.log_scalar("Mean_Episode_Length", mean_episode_length, self.num_timesteps)

            # Reset for next episode
            self.episode_rewards = []
            self.loss_values = []
            self.episode_lengths = []
        return True
    
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

# Configuration for hyperparameters with auto-tuning
@ex.config
def hyperparameters():
    learning_rate = 5e-4  # Default learning rate
    gamma = 0.995  # Default discount factor
    n_steps = 4096  # Default number of steps per update
    ent_coef = 0.001  # Default entropy coefficient
    clip_range = 0.2  # Default clip range for PPO
    total_timesteps = 300000  # Fixed value, not tuned
   
    # In your hyperparameter configuration or directly in the training setup:
    #n_steps = 512  # Adjust n_steps to ensure compatibility
    n_envs =1     # Assuming you are using a single environment
    batch_size = 4096  # Ensure this is a factor of n_steps * n_envs

# Function to train the PPO model with given hyperparameters
def train_ppo(_run, learning_rate, gamma, n_steps, ent_coef, clip_range, total_timesteps, n_envs, batch_size):
    device = check_device()
    os.makedirs("./ppo_tensorboard/", exist_ok=True)
    os.makedirs("./model_saved/", exist_ok=True)

    # Assume setup_web3, load_contracts, ReentrancyEnv, and PrintTimestepCallback are defined elsewhere
    web3 = setup_web3("http://127.0.0.1:7545")
    with open('deployed_contracts.json') as f:
        deployed_addresses = json.load(f)
    contracts = load_contracts("./build/contracts", deployed_addresses)

    vulnerable_contract = web3.eth.contract(
        address=Web3.toChecksumAddress(contracts['VulnerableContract']['address']),
        abi=contracts['VulnerableContract']['abi']
    )
    attacker_contract = web3.eth.contract(
        address=Web3.toChecksumAddress(contracts['Attacker']['address']),
        abi=contracts['Attacker']['abi']
    )
    attacker_account = web3.eth.accounts[1]

    detector = ReentrancyDetector(vulnerable_contract, web3)

    


    env = make_vec_env(lambda: ReentrancyEnv({
        'max_steps': 100,
        'max_balance': 100.0,
        'max_funds_drained': 1.0,
        'max_gas': 500000,
        'max_time': 60
    }, vulnerable_contract, attacker_contract, attacker_account, detector, web3, render_mode='human'), n_envs=n_envs)

    
    # Initialize the PPO model with the adjusted parameters
    model = PPO("MlpPolicy", env, learning_rate=learning_rate, gamma=gamma, 
                n_steps=n_steps, ent_coef=ent_coef, clip_range=clip_range,
                batch_size=batch_size, verbose=1, tensorboard_log="./ppo_tensorboard/", device=device)    
    
    callback = PrintTimestepCallback(_run=_run)
    model.learn(total_timesteps=total_timesteps, callback=callback)
    
    mean_reward = np.mean(callback.episode_rewards)
    
    # Log the mean reward of the training
    _run.log_scalar("mean_reward", mean_reward)

    # Save the trained model
    model_path = f"model_saved/trained_model_{mean_reward:.2f}.zip"
    model.save(model_path)
    _run.add_artifact(model_path)

    return mean_reward, model_path

# Main function for Sacred
@ex.automain
def main(_run, learning_rate, gamma, n_steps, ent_coef, clip_range, total_timesteps, n_envs, batch_size):
    mean_reward, model_path = train_ppo(_run, learning_rate, gamma, n_steps, ent_coef, clip_range, total_timesteps, n_envs, batch_size)
    print(f"Training completed with mean reward: {mean_reward}, model saved to {model_path}")

# Function to run with Optuna (if needed)
def run_with_optuna():
    best_reward = -np.inf
    best_model_path = None

    def objective(trial):
        nonlocal best_reward, best_model_path

        # Extract the hyperparameters suggested by Optuna
        learning_rate = trial.suggest_float('learning_rate', 1e-5, 1e-3, log=True)
        gamma = trial.suggest_float('gamma', 0.9, 0.999)
        n_steps = trial.suggest_int('n_steps', 128, 512)
        ent_coef = trial.suggest_float('ent_coef', 0.0001, 0.1, log=True)
        clip_range = trial.suggest_float('clip_range', 0.1, 0.4)
        # In your hyperparameter configuration or directly in the training setup:
        n_steps = 512  # Adjust n_steps to ensure compatibility
        n_envs = 1     # Assuming you are using a single environment
        batch_size = 128  # Ensure this is a factor of n_steps * n_envs

        # Run the Sacred experiment with the suggested hyperparameters
        run = ex.run(config_updates={
            "learning_rate": learning_rate,
            "gamma": gamma,
            "n_steps": n_steps,
            "ent_coef": ent_coef,
            "clip_range": clip_range,
            # In your hyperparameter configuration or directly in the training setup:
            "n_steps" : n_steps,  # Adjust n_steps to ensure compatibility
            "n_envs" : n_envs,     # Assuming you are using a single environment
            "batch_size" : batch_size  # Ensure this is a factor of n_steps * n_envs
        })

        # Get the result from the run
        result = run.result
        if result is None:
            return -np.inf

        mean_reward, model_path = result

        # Save the model if it is the best so far
        if mean_reward > best_reward:
            best_reward = mean_reward
            best_model_path = model_path
            print(f"New best model found: {model_path} with reward {mean_reward}")

        return mean_reward

    # Create Optuna study to optimize the PPO model
    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=50)

    # Output best hyperparameters
    print("Best hyperparameters: ", study.best_params)
    print(f"Best model saved at: {best_model_path}")

# Example of how to use Optuna tuning
# if __name__ == "__main__":
#     run_with_optuna()