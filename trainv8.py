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
from reentrancyEnv import ReentrancyEnv
from printTimestepCallback import PrintTimestepCallback

# Initialize Sacred Experiment
ex = Experiment("reentrancy_rl")

# Add observers
ex.observers.append(FileStorageObserver('./sacred_logs'))
ex.observers.append(MongoObserver(url='mongodb://localhost:27017', db_name='trainv8'))

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
    learning_rate = 1e-5  # Default learning rate
    gamma = 0.9930447770093623  # Default discount factor
    n_steps = 2048  # Default number of steps per update
    ent_coef = 0.01  # Default entropy coefficient
    clip_range = 0.1  # Default clip range for PPO
    total_timesteps = 1000000  # Fixed value, not tuned
   
    # In your hyperparameter configuration or directly in the training setup:
    #n_steps = 512  # Adjust n_steps to ensure compatibility
    n_envs =1     # Assuming you are using a single environment
    batch_size = 256  # Ensure this is a factor of n_steps * n_envs

# @ex.config
# def hyperparameters():
#     learning_rate = 0.0005555671852534937  # Default learning rate
#     gamma = 0.9930447770093623  # Default discount factor
#     n_steps = 2048  # Default number of steps per update
#     ent_coef = 0.0022495618240497583  # Default entropy coefficient
#     clip_range = 0.29918864741704365  # Default clip range for PPO
#     total_timesteps = 200000  # Fixed value, not tuned
   
#     # In your hyperparameter configuration or directly in the training setup:
#     #n_steps = 512  # Adjust n_steps to ensure compatibility
#     n_envs =1     # Assuming you are using a single environment
#     batch_size = 128  # Ensure this is a factor of n_steps * n_envs



# Function to train the PPO model with given hyperparameters
def train_ppo(_run, learning_rate, gamma, n_steps, ent_coef, clip_range, total_timesteps, n_envs, batch_size):
    device = check_device()
    os.makedirs("./ppo_tensorboard/", exist_ok=True)
    os.makedirs("./model_saved/", exist_ok=True)

    # Assume setup_web3, load_contracts, ReentrancyEnv, and PrintTimestepCallback are defined elsewhere
    # web3 = setup_web3("http://127.0.0.1:7545")
    # with open('deployed_contracts.json') as f:
    #     deployed_addresses = json.load(f)
    # contracts = load_contracts("./build/contracts", deployed_addresses)

    # vulnerable_contract = web3.eth.contract(
    #     address=Web3.toChecksumAddress(contracts['VulnerableContract']['address']),
    #     abi=contracts['VulnerableContract']['abi']
    # )
    # attacker_contract = web3.eth.contract(
    #     address=Web3.toChecksumAddress(contracts['Attacker']['address']),
    #     abi=contracts['Attacker']['abi']
    # )
    # attacker_account = web3.eth.accounts[1]

    # detector = ReentrancyDetector(vulnerable_contract, web3)

    


    env = make_vec_env(lambda: ReentrancyEnv({
        'max_steps': 100
    }, render_mode='human'), n_envs=n_envs)
    # vulnerable_contract, attacker_contract, attacker_account, detector, web3, render_mode='human'), n_envs=n_envs)

    
    # Initialize the PPO model with the adjusted parameters
    model = PPO("MlpPolicy", env, 
                #policy_kwargs=dict(net_arch=[256, 256]),
                learning_rate=learning_rate, gamma=gamma, 
                n_steps=n_steps, ent_coef=ent_coef, clip_range=clip_range,
                batch_size=batch_size, verbose=1, tensorboard_log="./ppo_tensorboard/", device=device)    
    
    callback = PrintTimestepCallback(_run=_run)
    model.learn(total_timesteps=total_timesteps, callback=callback)
    
    mean_reward = np.mean(callback.episode_rewards)
    
    # Log the mean reward of the training
    #_run.log_scalar("mean_reward", mean_reward)

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
        n_steps = 2048  # Adjust n_steps to ensure compatibility
        n_envs = 1     # Assuming you are using a single environment
        batch_size = 64  # Ensure this is a factor of n_steps * n_envs

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