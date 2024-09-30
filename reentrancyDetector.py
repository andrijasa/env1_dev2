# Reentrancy detection (not changed)


class ReentrancyDetector:
    def __init__(self, web3, target_contract):
        self.target_contract = target_contract
        # self.previous_block = web3.eth.block_number
        self.web3 = web3
        self.call_count = 0  # Initialize call count
        self.call_depth = 0  # Initialize call depth

    # def detect_reentrancy(self):
    #     latest_block = self.web3.eth.block_number
    #     block = self.web3.eth.getBlock(latest_block, full_transactions=True)
    #     tx = block.transactions[-1]
    #     call_count, call_depth = self.analyze_transaction(tx.hash)
    #     self.call_count = call_count if call_count > 1 else 0 # Your logic to set call_count
    #     self.call_depth = call_depth if call_count > 1 else 0 # Your logic to set call_depth
        #return call_count, call_depth if call_count > 1 or call_depth > 1 else 0, 0

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
                contract_address = self.target_contract.address.lower()

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
    
    def get_call_count(self):
        return self.call_count

    def get_call_depth(self):
        return self.call_depth

# Convert Web3 results (not changed)
def convert_attribute_dict(obj):
    if isinstance(obj, dict):
        return {k: convert_attribute_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_attribute_dict(i) for i in obj]
    else:
        return obj

