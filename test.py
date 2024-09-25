import gymnasium as gym
import torch
import torch.nn as nn
import torch.optim as optim
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import BaseCallback
from stable_baselines3.common.monitor import Monitor
from stable_baselines3.common.vec_env import SubprocVecEnv, VecNormalize
from stable_baselines3.common.utils import set_random_seed
from pettingzoo.mpe import simple_spread_v3
from stable_baselines3.common.logger import configure
import numpy as np

# Custom TensorBoard callback
class TensorboardCallback(BaseCallback):
    def __init__(self, verbose=0):
        super(TensorboardCallback, self).__init__(verbose)

    def _on_step(self) -> bool:
        return True

# Custom PettingZoo environment wrapper
class PettingZooEnvWrapper(gym.Env):
    def __init__(self, env):
        self.env = env
        self.agents = self.env.possible_agents
        self.num_agents = len(self.agents)
        self.observation_space = gym.spaces.Dict({
            agent: self.env.observation_space(agent) for agent in self.agents
        })
        self.action_space = gym.spaces.Dict({
            agent: self.env.action_space(agent) for agent in self.agents
        })

    def reset(self):
        observations = self.env.reset()
        return {agent: observations[agent] for agent in self.agents}

    def step(self, actions):
        observations, rewards, dones, infos = self.env.step(actions)
        return (
            {agent: observations[agent] for agent in self.agents},
            {agent: rewards[agent] for agent in self.agents},
            {agent: dones[agent] for agent in self.agents},
            {agent: infos[agent] for agent in self.agents},
        )

    def render(self, mode='human'):
        self.env.render(mode=mode)

    def close(self):
        self.env.close()

def make_env(seed=None):
    def _init():
        env = simple_spread_v3.parallel_env()
        env = PettingZooEnvWrapper(env)
        env = Monitor(env)
        if seed is not None:
            env.seed(seed)
        return env
    return _init

# Create the vectorized environment
n_envs = 8
seed = 42
env = SubprocVecEnv([make_env(seed + i) for i in range(n_envs)])
env = VecNormalize(env)

# Set up the model with PPO algorithm
model = PPO(
    "MlpPolicy",
    env,
    verbose=1,
    tensorboard_log="./ppo_simple_spread_tensorboard/",
    learning_rate=3e-4,
    n_steps=2048,
    batch_size=64,
    n_epochs=10,
    gamma=0.99,
    gae_lambda=0.95,
    clip_range=0.2,
    ent_coef=0.01,
    vf_coef=0.5,
    max_grad_norm=0.5,
    use_sde=True,
    sde_sample_freq=4,
)

# Configure TensorBoard logging
new_logger = configure("./ppo_simple_spread_tensorboard/", ["tensorboard"])
model.set_logger(new_logger)

# Train the model
model.learn(total_timesteps=1000000, callback=TensorboardCallback())

# Save the model
model.save("ppo_simple_spread_model")

# Optional: to load and continue training
# model = PPO.load("ppo_simple_spread_model", env=env)

# To visualize training with TensorBoard, run the following command in terminal:
# tensorboard --logdir=./ppo_simple_spread_tensorboard/
