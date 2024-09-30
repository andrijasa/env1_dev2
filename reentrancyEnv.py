# Custom environment for Reentrancy attack simulation
import gymnasium as gym
from gymnasium import spaces
import numpy as np
import time
from severityScore import SeverityScore



class ReentrancyEnv(gym.Env):
    metadata = {'render.modes': ['human']}

    def __init__(self, hyperparameters, render_mode=None):
        super(ReentrancyEnv, self).__init__()

        self.hyperparameters = hyperparameters
        self.max_steps = self.hyperparameters['max_steps']

        # Initial fixed balances for the contracts (in Ether)
        self.initial_vulnerable_contract_balance = 10.0  # Initial fixed balance in Ether
        self.initial_attacker_contract_balance = 10.0    # Initial fixed balance in Ether

        # Current balances that will change during the episode
        self.fixed_vulnerable_contract_balance = self.initial_vulnerable_contract_balance
        self.fixed_attacker_contract_balance = self.initial_attacker_contract_balance

        # Define action space: 0 = prevent, 1 = allow
        self.action_space = spaces.Discrete(2)

        # Define observation space (7-dimensional state space based on attack profile)
        self.observation_space = spaces.Box(low=0, high=1, shape=(9,), dtype=np.float32)

        # Initialize internal state
        self.state = np.zeros(9)
        self.current_step = 0
        self.last_transaction_time = None
        self.render_mode = render_mode

        self.reward_history = []  # Initialize reward history for dynamic scaling

        # Initial epsilon for random action sampling (epsilon-greedy)
        self.epsilon = 1.0  # High epsilon means more exploration initially
        self.epsilon_min = 0.1  # Minimum epsilon value to decay towards
        self.epsilon_decay = 0.995  # Rate at which epsilon decays after each episode



    def reset(self, seed=None, options=None):
        """Reset the environment to its initial state with meaningful default values."""

        # Handle the seed for reproducibility
        if seed is not None:
            self.seed(seed)

        # Reset balances to their initial values
        self.fixed_vulnerable_contract_balance = self.initial_vulnerable_contract_balance
        self.fixed_attacker_contract_balance = self.initial_attacker_contract_balance

        # Reset the current step counter and transaction time
        self.current_step = 0
        self.last_transaction_time = time.time()

        # Initialize the balances to their fixed values
        normalized_reentrancy_detected = 0.0
        normalized_vulnerable_balance = min(self.fixed_vulnerable_contract_balance / 100.0, 1.0)
        normalized_attacker_balance = min(self.fixed_attacker_contract_balance / 100.0, 1.0)

        # Initialize the rest of the state to default starting values
        normalized_funds_drained = 0.0  # No funds have been drained at the start
        normalized_gas_used = 0.0       # No gas used at the start
        normalized_call_count = 0.0
        normalized_call_depth = 0.0     # No call depth at the start
        severity_score = 0.0            # Initial severity score is zero
        action = 0.0                    # No action taken yet, initialize with prevent (0)

        # Set the initial state, including the new variables
        self.state = np.array([
            normalized_reentrancy_detected,
            normalized_vulnerable_balance,  # Fixed vulnerable contract balance
            normalized_attacker_balance,    # Fixed attacker contract balance
            normalized_funds_drained,       # Funds drained, initially zero
            normalized_gas_used,            # Gas used, initially zero
            normalized_call_count,
            normalized_call_depth,          # Call depth, initially zero
            severity_score,                 # Initial severity score, zero
            action                          # No action taken at the start
        ], dtype=np.float32)

        return self.state, {}


    def seed(self, seed=None):
        """Set the seed for reproducibility."""
        np.random.seed(seed)

    def step(self, action):
        """Take a step in the environment."""

        # Simulate attacker and get the resulting attack profile
        reentrancy_detected, funds_drained, call_count, gas_used, call_depth = self._simulate_attacker()

        # Calculate the reward based on severity level of the attack
        reward = self._calculate_reward(reentrancy_detected, funds_drained, call_count, gas_used, call_depth, action)

        # Update the internal state of the environment, incorporating the new variables
        self.state = self._update_state(reentrancy_detected, funds_drained, call_count, gas_used, call_depth, action)

        # Terminate after a certain number of steps (optional)
        self.current_step += 1
        truncated = False
        terminated = self.current_step >= self.max_steps

        return self.state, reward, terminated, truncated, {
            'reentrancy_detected': reentrancy_detected,
            'balance': self.state[1],
            'attacker_balance': self.state[2],
            'funds_drained': funds_drained,
            'gas_used': gas_used,
            'call_count': call_count,
            'call_depth': call_depth,
            'severity_score': self.state[7],
            'action': action
            
        }

    def _simulate_attacker(self):
        """
        Simulate an attack scenario based on the current state of the environment.
        """

        # Extract current state information
        reentrancy_detected, normalized_vulnerable_balance, normalized_attacker_balance, normalized_funds_drained, \
        normalized_gas_used, normalized_call_count, normalized_call_depth, previous_severity, action = self.state

        # Simulate the attacker adjusting their strategy based on the current state
        if normalized_vulnerable_balance > 0.5 and previous_severity < 0.5:
            call_count = np.random.poisson(lam=5)  # Higher number of function calls in attack
            call_depth = np.random.geometric(p=0.4)  # Shallower call depth but more frequent
            gas_used = np.random.uniform(low=250000, high=500000)  # Higher gas usage
            funds_drained = np.abs(np.random.normal(loc=0.001, scale=0.0005))  # Draining more funds
        else:
            call_count = np.random.poisson(lam=2)  # Fewer function calls
            call_depth = np.random.geometric(p=0.2)  # Deeper call depth, fewer overall calls
            gas_used = np.random.uniform(low=21000, high=250000)  # Lower gas usage
            funds_drained = np.abs(np.random.normal(loc=0.0005, scale=0.0001))  # Draining fewer funds

        # Ensure funds drained does not exceed the normalized vulnerable balance
        funds_drained = min(funds_drained, normalized_vulnerable_balance * 100.0 / self.fixed_vulnerable_contract_balance)

        # Update contract balances based on the funds drained
        self.fixed_vulnerable_contract_balance -= funds_drained
        self.fixed_attacker_contract_balance += funds_drained

        # Determine if a reentrancy attack is detected based on the attacker's strategy
        reentrancy_detected = call_count > 2 and call_depth > 2  # Simple rule for detection

        return reentrancy_detected, funds_drained, call_count, gas_used, call_depth

    def _calculate_reward(self, reentrancy_detected, funds_drained, call_count, gas_used, call_depth, allowed):
        # Calculate severity scores based on the attack profile
        funds_severity = SeverityScore._calculate_funds_severity(funds_drained)
        call_count_severity = SeverityScore._calculate_call_count_severity(call_count)
        call_depth_severity = SeverityScore._calculate_call_depth_severity(call_depth)
        gas_used_severity = SeverityScore._calculate_gas_severity(gas_used)

        # Total severity score for the attack
        severity_score = funds_severity + call_count_severity + call_depth_severity + gas_used_severity

        # Reward/penalty scaling factors
        block_reward_scale = 50      # Reward if reentrancy detected and blocked
        allowed_penalty_scale = 20   # Penalty for allowing an attack
        safe_transaction_reward = 5  # Reward for allowing a safe transaction
        minor_penalty_scale = 10     # Penalty for small mistakes
        blocking_safe_penalty = 10   # Penalty for blocking safe transactions

        # Initialize the reward
        reward = 0

        # Reward strategy
        if reentrancy_detected and not allowed:
            # Reward for successfully blocking a detected attack
            reward += block_reward_scale * severity_score
        elif reentrancy_detected and allowed:
            # Penalty for failing to block a detected attack
            reward -= allowed_penalty_scale * severity_score
        elif not reentrancy_detected and allowed:
            # Reward for allowing safe transactions
            reward += safe_transaction_reward
        elif not reentrancy_detected and not allowed:
            # Penalty for blocking a safe transaction
            reward -= blocking_safe_penalty

        # Penalize proportionally to the funds drained
        if funds_drained > 0:
            reward -= funds_drained * 10  # Lower penalty scale for drained funds
        
        # Reward for minimizing gas usage (encouraging efficiency)
        reward += (1 - min(gas_used / 300000, 1.0)) * 5  # Smaller scale to avoid over-penalization
        
        # Encourage the agent to minimize call depth (simpler, safer interactions)
        reward += (1 - min(call_depth / 10, 1.0)) * 3  # Encourage shallower call depth

        # Penalty if the severity score is high but no action was taken
        if severity_score > 6 and allowed:
            reward -= minor_penalty_scale * severity_score  # Small penalty for high severity allowed

        # Additional reward for not allowing any funds to be drained
        if funds_drained == 0 and not reentrancy_detected:
            reward += 5  # Extra reward for fully safe transactions
        
        # Normalize and ensure the reward is not too extreme
        reward = max(min(reward, 100), -100)

        return reward

    def select_action(self, current_policy):
        """Select an action using epsilon-greedy strategy."""
        if np.random.rand() < self.epsilon:
            # Explore: choose a random action
            action = self.action_space.sample()
        else:
            # Exploit: choose the best action based on the current policy
            action = np.argmax(current_policy)
        return action
    
    def _update_state(self, reentrancy_detected, funds_drained, call_count, gas_used, call_depth, action):
        """
        Update the environment's internal state based on the latest transaction and incorporate new variables.
        """
        # Calculate severity scores based on the attack profile
        funds_severity = SeverityScore._calculate_funds_severity(funds_drained)
        call_count_severity = SeverityScore._calculate_call_count_severity(call_count)
        call_depth_severity = SeverityScore._calculate_call_depth_severity(call_depth)
        gas_used_severity = SeverityScore._calculate_gas_severity(gas_used)

        # Total severity score
        severity_score = funds_severity + call_count_severity + call_depth_severity + gas_used_severity

        # Normalize new values for state
        normalized_reentrancy_detected = float(reentrancy_detected)  # 0.0 if False, 1.0 if True
        normalized_funds_drained = min(funds_drained / 1.0, 1.0)
        normalized_call_count = min(call_count / 10, 1.0)  # Assuming a maximum of 10 calls
        normalized_gas_used = min(gas_used / 500000, 1.0)
        normalized_call_depth = min(call_depth / 10, 1.0)
        normalized_action = float(action)  # 0 for prevent, 1 for allow

        # Set maximum expected balance for normalization purposes
        max_balance = max(self.initial_vulnerable_contract_balance, self.initial_attacker_contract_balance)

        # Normalize and update the state
        normalized_vulnerable_balance = min(self.fixed_vulnerable_contract_balance / max_balance, 1.0)
        normalized_attacker_balance = min(self.fixed_attacker_contract_balance / max_balance, 1.0)

        # Incorporate new values into the state array
        self.state = np.array([
            normalized_reentrancy_detected,
            normalized_vulnerable_balance,     # Updated vulnerable contract balance
            normalized_attacker_balance,       # Updated attacker contract balance
            normalized_funds_drained,          # Funds drained, normalized
            normalized_gas_used,               # Gas used, normalized
            normalized_call_count,
            normalized_call_depth,             # Call depth, normalized
            severity_score / 12.0,             # Severity score, normalized (max possible severity score is 12)
            normalized_action                  # Action taken (0 for prevent, 1 for allow)
        ], dtype=np.float32)

        return self.state


    
    # Metric	Low Severity (1)	Moderate Severity (2)	High Severity (3)
    # Funds Drained	0 - 0.001 ETH	0.001 - 0.01 ETH	> 0.01 ETH
    # Call Count	1 - 2 function calls	3 - 5 function calls	> 5 function calls
    # Call Depth	1 - 3 levels	4 - 6 levels	> 6 levels
    # Gas Used	< 100,000 gas	100,000 - 300,000 gas	> 300,000 gas

    def render(self, mode='human'):
        if mode == 'human':
            print(f"Step: {self.current_step}, Balance: {self.state[0]}")
        elif mode == 'rgb_array':
            pass

    def close(self):
        """Clean up resources (optional)."""
        pass
