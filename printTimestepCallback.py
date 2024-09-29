# Custom callback for logging and monitoring

import time
import numpy as np
from stable_baselines3.common.callbacks import BaseCallback

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


            # Log additional metrics if they exist
            if 'infos' in self.locals and 'episode' in self.locals['infos'][0]:
                self._run.log_scalar('rollout/ep_len_mean', self.locals['infos'][0]['episode'].get('l', 0), self.num_timesteps)
                self._run.log_scalar('rollout/ep_rew_mean', self.locals['infos'][0]['episode'].get('r', 0), self.num_timesteps)
            if 'fps' in self.locals:
                self._run.log_scalar('time/fps', self.locals['fps'], self.num_timesteps)
            if 'iteration' in self.locals:
                self._run.log_scalar('time/iterations', self.locals['iteration'], self.num_timesteps)
            if 'time_elapsed' in self.locals:
                self._run.log_scalar('time/time_elapsed', self.locals['time_elapsed'], self.num_timesteps)
            if 'total_timesteps' in self.locals:
                self._run.log_scalar('time/total_timesteps', self.locals['total_timesteps'], self.num_timesteps)
            if 'approx_kl' in self.locals:
                self._run.log_scalar('train/approx_kl', self.locals['approx_kl'], self.num_timesteps)
            if 'clip_fraction' in self.locals:
                self._run.log_scalar('train/clip_fraction', self.locals['clip_fraction'], self.num_timesteps)
            if 'clip_range' in self.locals:
                self._run.log_scalar('train/clip_range', self.locals['clip_range'], self.num_timesteps)
            if 'entropy_loss' in self.locals:
                self._run.log_scalar('train/entropy_loss', self.locals['entropy_loss'], self.num_timesteps)
            if 'explained_variance' in self.locals:
                self._run.log_scalar('train/explained_variance', self.locals['explained_variance'], self.num_timesteps)
            if 'learning_rate' in self.locals:
                self._run.log_scalar('train/learning_rate', self.locals['learning_rate'], self.num_timesteps)
            if 'loss' in self.locals:
                self._run.log_scalar('train/loss', self.locals['loss'], self.num_timesteps)
            if 'n_updates' in self.locals:
                self._run.log_scalar('train/n_updates', self.locals['n_updates'], self.num_timesteps)
            if 'policy_gradient_loss' in self.locals:
                self._run.log_scalar('train/policy_gradient_loss', self.locals['policy_gradient_loss'], self.num_timesteps)
            if 'value_loss' in self.locals:
                self._run.log_scalar('train/value_loss', self.locals['value_loss'], self.num_timesteps)

            # Reset for next episode
            self.episode_rewards = []
            self.loss_values = []
            self.episode_lengths = []
        return True
    
    def _on_rollout_end(self) -> None:
        # Manually calculate and log the loss
        policy_loss = self.model.logger.name_to_value.get('train/policy_gradient_loss', 0)
        value_loss = self.model.logger.name_to_value.get('train/value_loss', 0)
        entropy_loss = self.model.logger.name_to_value.get('train/entropy_loss', 0)
        
        # Calculate total loss
        total_loss = policy_loss + value_loss + entropy_loss
        self._run.log_scalar('train/total_loss', total_loss, self.num_timesteps)