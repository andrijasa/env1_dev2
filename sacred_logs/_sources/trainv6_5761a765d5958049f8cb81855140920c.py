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


# Initialize Sacred Experiment
ex = Experiment("reentrancy_rl")

# Add observers
ex.observers.append(FileStorageObserver('./sacred_logs'))
# Assuming MongoDB is running locally on the default port and database 'sacred' exists
ex.observers.append(MongoObserver(url='mongodb://localhost:27017', db_name='env1_dev2'))


def check_device(use_gpu=True):
    """
    Check and select the device for computation (CPU or GPU).

    Args:
        use_gpu (bool): If True, attempt to use GPU if available. If False, use CPU.

    Returns:
        torch.device: The selected device.
    """
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

def setup_web3(ganache_url):
    web3 = Web3(Web3.HTTPProvider(ganache_url))
    web3.middleware_onion.inject(geth_poa_middleware, layer=0)
    return web3


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


def risk_score(transaction, malicious_addresses):
    if transaction['to'] in malicious_addresses:
        return True
    return False


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


def convert_attribute_dict(obj):
    if isinstance(obj, dict):
        return {k: convert_attribute_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_attribute_dict(i) for i in obj]
    else:
        return obj


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
            reentrancy_detected, funds_drained, call_count, gas_used, call_depth = self._simulate_attacker()
            reward = self._calculate_reward(reentrancy_detected, funds_drained, call_count, True)
        else:
            reentrancy_detected, funds_drained, call_count, gas_used, call_depth = self._simulate_attacker()
            reward = self._calculate_reward(reentrancy_detected, funds_drained, call_count, False)

        self.last_transaction_time = current_time
        return reward, terminated, truncated, funds_drained, call_count, call_depth, gas_used

    def _calculate_reward(self, reentrancy_detected, funds_drained, call_count, allowed):
        reward = -100 if reentrancy_detected else 5
        reward -= 50 if funds_drained > 0 else 0
        reward -= 10 * call_count if reentrancy_detected else 0
        reward += 50 if not allowed and reentrancy_detected else -5
        return reward

    def _simulate_attacker(self):
        reentrancy_detected = np.random.choice([True, False], p=[0.3, 0.7])
        funds_drained = abs(np.random.normal(0.0001, 0.00005))
        call_count = np.random.choice(range(1, 6), p=[0.5, 0.3, 0.1, 0.05, 0.05])
        gas_values = range(21000, 500001, 10000)
        gas_used = np.random.choice(gas_values, p=np.linspace(0.6, 0.01, len(gas_values)) / np.sum(np.linspace(0.6, 0.01, len(gas_values))))
        call_depth_values = range(1, 13)
        call_depth = np.random.choice(call_depth_values, p=np.linspace(0.4, 0.05, len(call_depth_values)) / np.sum(np.linspace(0.4, 0.05, len(call_depth_values))))
        return reentrancy_detected, funds_drained, call_count, gas_used, call_depth

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


class PrintTimestepCallback(BaseCallback):
    def __init__(self, verbose=0, _run=None):
        super(PrintTimestepCallback, self).__init__(verbose)
        self.start_time = None
        self.episode_start_time = None
        self.episode_num = 0
        self.episode_rewards = []
        self._run = _run

    def _on_training_start(self) -> None:
        self.start_time = time.time()

    def _on_step(self) -> bool:
        if self.episode_start_time is None:
            self.episode_start_time = time.time()

        reward = self.locals['rewards'][0]
        self.episode_rewards.append(reward)

        if self.locals['dones'][0]:
            self.episode_num += 1
            mean_reward = sum(self.episode_rewards) / len(self.episode_rewards)
            episode_duration = time.time() - self.episode_start_time
            formatted_episode_duration = time.strftime("%H:%M:%S", time.gmtime(episode_duration))
            elapsed_time = time.time() - self.start_time
            formatted_total_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
            print(f"Total Time: {formatted_total_time} | Episode Duration: {formatted_episode_duration} | Timestep: {self.num_timesteps} | Episode: {self.episode_num} | Mean Reward: {mean_reward:.2f}")
            self.episode_rewards = []
            self._run.log_scalar("Timestamp_reward", mean_reward, self.episode_num)
            
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

@ex.config
def hyperparameters():
    ganache_url = "http://127.0.0.1:7545"
    contracts_path = "./build/contracts"
    log_dir = "./ppo_tensorboard/"
    max_steps = 100
    max_balance = 100.0
    max_funds_drained = 1.0
    max_gas = 500000
    max_time = 60
    total_timesteps = 5000


@ex.automain
def main(_run, ganache_url, contracts_path, log_dir, max_steps, max_balance, max_funds_drained, max_gas, max_time, total_timesteps):
    # Log hyperparameters to Sacred
    # _run.log_scalar("max_steps", max_steps)
    # _run.log_scalar("max_balance", max_balance)
    # _run.log_scalar("max_funds_drained", max_funds_drained)
    # _run.log_scalar("max_gas", max_gas)
    # _run.log_scalar("max_time", max_time)
    # _run.log_scalar("total_timesteps", total_timesteps)

    device = check_device();
    web3 = setup_web3(ganache_url)

    os.makedirs(log_dir, exist_ok=True)

    with open('deployed_contracts.json') as f:
        deployed_addresses = json.load(f)

    contracts = load_contracts(contracts_path, deployed_addresses)
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
        'max_steps': max_steps,
        'max_balance': max_balance,
        'max_funds_drained': max_funds_drained,
        'max_gas': max_gas,
        'max_time': max_time
    }, vulnerable_contract, attacker_contract, attacker_account, detector, web3, render_mode='human'), n_envs=1)

    model = PPO("MlpPolicy", env, verbose=1, tensorboard_log=log_dir, device=device)
    new_logger = configure(log_dir, ["stdout", "csv", "tensorboard"])
    model.set_logger(new_logger)

    callback = PrintTimestepCallback(_run=_run)

    model.learn(total_timesteps=total_timesteps, callback=callback)
    model.save("ppo_defender")

    _run.add_artifact("ppo_defender.zip")
    

    model = PPO.load("ppo_defender")

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
        
        # Log episode results to Sacred
        _run.log_scalar("episode_reward", episode, total_reward)
        
        obs = env.reset()

        
