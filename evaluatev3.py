import os
import numpy as np
import gymnasium as gym
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from stable_baselines3.common.evaluation import evaluate_policy
import matplotlib.pyplot as plt
from reentrancyEnv import ReentrancyEnv  # Ensure AlteredReentrancyEnv is correctly imported


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
    
# Load the best model
model_path = "./model_saved/trained_model_31.61.zip"
model = PPO.load(model_path)

# Set up the original and altered evaluation environments
eval_env = DummyVecEnv([lambda: ReentrancyEnv({
    'max_steps': 100
})])

altered_env_1 = DummyVecEnv([lambda: AlteredReentrancyEnv(hyperparameters={'max_steps': 100}, noise_level=0.1, altered_param=1.2)])
altered_env_2 = DummyVecEnv([lambda: AlteredReentrancyEnv(hyperparameters={'max_steps': 100}, noise_level=0.2, altered_param=1.5)])

# Define the condition for success
def is_success(funds_drained, reentrancy_detected, action_taken, severity_score):
    return (funds_drained < 0.001) or (reentrancy_detected == 1 and severity_score < (3/12))

# Function to evaluate the model in a given environment
def evaluate_model_in_env(env, n_episodes=100):
    actions_taken = []
    episode_rewards = []
    episode_lengths = []
    successes = 0

    for episode in range(n_episodes):
        obs = env.reset()
        done = False
        total_reward = 0
        steps = 0
        episode_success = False
        while not done:
            action, _states = model.predict(obs, deterministic=True)
            step_result = env.step(action)
            
            if len(step_result) == 5:
                obs, reward, done, truncated, info = step_result
            else:
                obs, reward, done, info = step_result
                truncated = False

            total_reward += reward
            steps += 1

            info = info[0]  # Assuming a single environment in the DummyVecEnv

            # Append action to the actions list
            actions_taken.append(action)

            funds_drained = info.get('funds_drained', 0)
            reentrancy_detected = info.get('reentrancy_detected', 0)
            severity_score = info.get('severity_score', 0)

            if is_success(funds_drained, reentrancy_detected, action, severity_score):
                episode_success = True

        if episode_success:
            successes += 1

        episode_rewards.append(total_reward)
        episode_lengths.append(steps)

    actions = np.array(actions_taken)
    average_reward = np.mean(episode_rewards)
    std_reward = np.std(episode_rewards)
    average_length = np.mean(episode_lengths)
    success_rate = (successes / n_episodes) * 100
    failure_rate = 100 - success_rate

    return {
        'episode_rewards': episode_rewards,
        'std_reward': std_reward,
        'average_length': average_length,
        'success_rate': success_rate,
        'failure_rate': failure_rate,
        'actions': actions
    }

# Evaluate in the original and altered environments
results_original = evaluate_model_in_env(eval_env)
results_altered_1 = evaluate_model_in_env(altered_env_1)
results_altered_2 = evaluate_model_in_env(altered_env_2)

# Print results
def print_results(results, env_name):
    print(f"\nResults for {env_name}:")
    print(f"Success Rate: {results['success_rate']:.2f}%")
    print(f"Failure Rate: {results['failure_rate']:.2f}%")
    print(f"Average Reward per Episode: {np.mean(results['episode_rewards']):.2f} ± {results['std_reward']:.2f}")
    print(f"Average Steps per Episode: {results['average_length']:.2f}")

    # Print action distribution
    unique, counts = np.unique(results['actions'], return_counts=True)
    action_counts = dict(zip(unique, counts))

    for action in range(2):  # Assuming 2 discrete actions: prevent (0) and allow (1)
        print(f"Action {action}: {action_counts.get(action, 0)} times ({(action_counts.get(action, 0) / len(results['actions'])) * 100:.2f}%)")

    # Plot action distribution
    plt.hist(results['actions'], bins=np.arange(3) - 0.5, density=True)
    plt.xticks([0, 1], ['Prevent', 'Allow'])  # Adding labels for clarity
    plt.xlabel('Action')
    plt.ylabel('Frequency')
    plt.title(f'Action Distribution - {env_name}')
    plt.show()

# Print and plot results for each environment
print_results(results_original, "Original Environment")
print_results(results_altered_1, "Altered Environment 1")
print_results(results_altered_2, "Altered Environment 2")

# Plot the rewards over episodes for each environment
plt.plot(results_original['episode_rewards'], label='Original Environment')
plt.plot(results_altered_1['episode_rewards'], label='Altered Environment 1')
plt.plot(results_altered_2['episode_rewards'], label='Altered Environment 2')
plt.xlabel('Episode')
plt.ylabel('Reward')
plt.title('Episode Rewards across Environments')
plt.legend()
plt.show()
