import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import BaseCallback, CheckpointCallback
from sacred import Experiment
from sacred.observers import MongoObserver

# Set up Sacred experiment
ex = Experiment('ppo_simple_spread')

# Add MongoDB observer
ex.observers.append(MongoObserver(url='mongodb://localhost:27017', db_name='sacred'))

@ex.config
def my_config():
    env_id = "CartPole-v1"  # Replace with the actual environment ID
    total_timesteps = 10000
    save_path = './logs/'
    save_freq = 1000

class CustomCallback(BaseCallback):
    def __init__(self, verbose=0):
        super(CustomCallback, self).__init__(verbose)
        self.episode_rewards = []

    def _on_step(self) -> bool:
        if self.locals['dones']:
            reward = self.locals['rewards']
            if isinstance(reward, np.ndarray):
                reward = reward.tolist()  # Convert numpy array to list
            self.episode_rewards.append(reward)
            
            # Flatten the list of rewards
            flat_rewards = [item for sublist in self.episode_rewards for item in sublist]
            
            mean_reward = sum(flat_rewards) / len(flat_rewards)
            ex.log_scalar('mean_reward', mean_reward, self.num_timesteps)
            
            # Log additional metrics if they exist
            if 'infos' in self.locals and 'episode' in self.locals['infos'][0]:
                ex.log_scalar('rollout/ep_len_mean', self.locals['infos'][0]['episode'].get('l', 0), self.num_timesteps)
                ex.log_scalar('rollout/ep_rew_mean', self.locals['infos'][0]['episode'].get('r', 0), self.num_timesteps)

        return True

    def _on_rollout_end(self) -> None:
        # Manually calculate and log the loss
        policy_loss = self.model.logger.name_to_value.get('train/policy_gradient_loss', 0)
        value_loss = self.model.logger.name_to_value.get('train/value_loss', 0)
        entropy_loss = self.model.logger.name_to_value.get('train/entropy_loss', 0)
        
        # Calculate total loss
        total_loss = policy_loss + value_loss + entropy_loss
        ex.log_scalar('train/total_loss', total_loss, self.num_timesteps)
        
       


@ex.automain
def main(env_id, total_timesteps, save_path, save_freq):
    # Create the environment
    vec_env = make_vec_env(env_id, n_envs=1)

    # Create the PPO model
    model = PPO("MlpPolicy", vec_env, verbose=1)

    # Create the callbacks
    checkpoint_callback = CheckpointCallback(save_freq=save_freq, save_path=save_path, name_prefix='ppo_model')
    custom_callback = CustomCallback()

    # Train the model with the callbacks
    model.learn(total_timesteps=total_timesteps, callback=[checkpoint_callback, custom_callback])

    # Save the model
    model.save("ppo_simple_spread")

    # Test the trained model
    obs = vec_env.reset()
    for _ in range(1000):
        action, _states = model.predict(obs)
        obs, rewards, dones, infos = vec_env.step(action)
        vec_env.render()

    # Close the environment
    vec_env.close()