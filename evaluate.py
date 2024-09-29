import numpy as np
import gymnasium as gym
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from trainv7 import ReentrancyEnv

# Assuming ReentrancyEnv is your original environment
class AlteredReentrancyEnv(ReentrancyEnv):
    def __init__(self, hyperparameters, noise_level=0.1, altered_param=1.2, render_mode=None):
        super(AlteredReentrancyEnv, self).__init__(hyperparameters, render_mode)
        self.noise_level = noise_level
        self.altered_param = altered_param

    def reset(self, seed=None, options=None):
        state, info = super().reset(seed, options)
        # Modify initial conditions
        self.state = self.state * self.altered_param
        return self.state, info

    def step(self, action):
        state, reward, terminated, truncated, info = super().step(action)
        # Add noise to the reward
        reward += np.random.normal(0, self.noise_level)
        return state, reward, terminated, truncated, info

    
# Load the trained model
model = PPO.load("model_saved/trained_model_20.10.zip")

# Original environment
original_env = DummyVecEnv([lambda: ReentrancyEnv(hyperparameters={'max_steps': 100})])

# Altered environment with noise and modified parameters
altered_env_1 = DummyVecEnv([lambda: AlteredReentrancyEnv(hyperparameters={'max_steps': 100}, noise_level=0.1, altered_param=1.2)])
altered_env_2 = DummyVecEnv([lambda: AlteredReentrancyEnv(hyperparameters={'max_steps': 100}, noise_level=0.2, altered_param=1.5)])

# List of environments for validation
envs_to_test = [original_env, altered_env_1, altered_env_2]
env_names = ["Original Environment", "Altered Environment 1", "Altered Environment 2"]

# Function to evaluate the model in different environments
def evaluate_model(model, envs, env_names, episodes=10):
    for env, name in zip(envs, env_names):
        print(f"\nTesting in {name}")
        for episode in range(episodes):
            obs = env.reset()
            total_reward = 0
            done = False
            action_counts = np.zeros(env.action_space.n)  # Initialize a count array for actions
            
            while not done:
                action, _ = model.predict(obs)
                action_counts[action] += 1  # Count each action
                obs, reward, done, info = env.step(action)
                total_reward += reward
            
            print(f"Episode {episode + 1}: Total Reward = {total_reward}")
            print(f"Action Counts: {action_counts}")

    
# Evaluate the model
evaluate_model(model, envs_to_test, env_names)
