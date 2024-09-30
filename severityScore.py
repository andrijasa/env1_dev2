

class SeverityScore:
    
    def _calculate_funds_severity(funds_drained):
        """Calculate the severity based on the amount of funds drained."""
        if funds_drained < 0.001:
            return 1
        elif funds_drained < 0.01:
            return 2
        else:
            return 3

    def _calculate_call_count_severity(call_count):
        """Calculate the severity based on the number of calls made."""
        if call_count <= 2:
            return 1
        elif call_count <= 5:
            return 2
        else:
            return 3

    def _calculate_call_depth_severity(call_depth):
        """Calculate the severity based on the call depth."""
        if call_depth <= 3:
            return 1
        elif call_depth <= 6:
            return 2
        else:
            return 3

    def _calculate_gas_severity(gas_used):
        """Calculate the severity based on gas used."""
        if gas_used < 100000:
            return 1
        elif gas_used < 300000:
            return 2
        else:
            return 3


