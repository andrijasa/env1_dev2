import os
import numpy as np
import gymnasium as gym
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from stable_baselines3.common.evaluation import evaluate_policy
import matplotlib.pyplot as plt
from trainv7 import ReentrancyEnv


# Load the best model
model_path = "./model_saved/trained_model_20.10.zip"  # Replace <mean_reward> with the actual value
model = PPO.load(model_path)

# Set up the evaluation environment
eval_env = DummyVecEnv([lambda: ReentrancyEnv({
    'max_steps': 100,
    'max_balance': 100.0,
    'max_funds_drained': 1.0,
    'max_gas': 500000,
    'max_time': 60
})])

# Define the condition for success
def is_success(funds_drained, reentrancy_detected, action_taken, severity_score):
    # Allow some funds to be drained but consider it a success if the severity is low
    return (funds_drained < 0.001) or (reentrancy_detected == 1 and severity_score < (3/12))

# Initialize lists to store episode actions
actions_taken = []

n_episodes = 100
episode_rewards = []
episode_lengths = []
successes = 0
failures = 0

for episode in range(n_episodes):
    obs = eval_env.reset()
    done = False
    total_reward = 0
    steps = 0
    while not done:
        action, _states = model.predict(obs, deterministic=True)
        step_result = eval_env.step(action)
        # Unpack step_result based on its length
        if len(step_result) == 5:
            obs, reward, done, truncated, info = step_result
        else:
            obs, reward, done, info = step_result
            truncated = False  # Set truncated to False if it's not returned

        total_reward += reward
        steps += 1

         # Access the first environment's info dictionary
        info = info[0]  # Assuming a single environment in the DummyVecEnv


        # Append action to the actions list
        actions_taken.append(action)
        
        # Extract relevant info from the environment's step output
        funds_drained = info.get('funds_drained', 0)
        reentrancy_detected = info.get('reentrancy_detected', 0)
        severity_score = info.get('severity_score', 0)

        # Convert action to a list for printing
        action_list = action.tolist()
        # Convert reward to a scalar for printing
        reward_scalar = reward.item() if isinstance(reward, np.ndarray) else reward

        #print(f"Episode: {episode + 1}, Step: {steps}, Action: {action_list}, Reward: {reward_scalar:.2f}, Funds Drained: {funds_drained}, Reentrancy Detected: {reentrancy_detected}, Severity Score: {severity_score:.2f}")
        # Check if this episode is a success
        if is_success(funds_drained, reentrancy_detected, action, severity_score):
            successes += 1
        else:
            failures += 1
            #print(f"Episode: {episode + 1}, Step: {steps}, Action: {action_list}, Reward: {reward_scalar:.2f}, Funds Drained: {funds_drained}, Reentrancy Detected: {reentrancy_detected}, Severity Score: {severity_score:.2f}")


    episode_rewards.append(total_reward)
    episode_lengths.append(steps)

# Convert actions to numpy array for analysis
actions = np.array(actions_taken)

# Calculate statistics
average_reward = np.mean(episode_rewards)
average_length = np.mean(episode_lengths)
success_rate = (successes / (n_episodes * 100))*100
failure_rate = (failures / (n_episodes * 100))*100

print(f"Success Rate: {success_rate:.2f}%")
print(f"Failure Rate: {failure_rate:.2f}%")

print(f"Average Reward per Episode: {average_reward:.2f}")
print(f"Average Steps per Episode: {average_length:.2f}")

# Plot the rewards over episodes
plt.plot(episode_rewards)
plt.xlabel('Episode')
plt.ylabel('Reward')
plt.title('Episode Rewards')
plt.show()


# Assuming `actions` is your numpy array of actions taken by the agent
action_space_size = 2  # For two discrete actions: prevent (0) and allow (1)

# Calculate the counts for each action
unique, counts = np.unique(actions, return_counts=True)
action_counts = dict(zip(unique, counts))

# Print the counts for each action
for action in range(action_space_size):
    print(f"Action {action}: {action_counts.get(action, 0)} times ({(action_counts.get(action, 0) / len(actions)) * 100:.2f}%)")


plt.hist(actions, bins=np.arange(action_space_size + 1) - 0.5, density=True)
plt.xlabel('Action')
plt.ylabel('Frequency')
plt.title('Action Distribution')
plt.show()
