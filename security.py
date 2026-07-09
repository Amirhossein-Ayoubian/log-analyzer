from collections import Counter

class SecurityDetector:
    """
    Analyzes parsed log entries to detect security anomalies and malicious activities.
    """
    def __init__(self, threshold=5):
        self.threshold = threshold
        self.failed_login_counter = Counter()

    def inspect(self, entry):
        """
        Inspects a single log entry for suspicious behavior.
        """
        if entry.status in (401, 403):
            self.failed_login_counter[entry.ip] += 1

    def print_alerts(self):
        """
        Prints security alerts if any IP exceeds the failed attempts threshold.
        """
        print(f"Security Alert - Potential Brute Force Attacks (Failed Requests > {self.threshold}):")
        
        suspicious_found = False
        for ip, failed_count in self.failed_login_counter.items():
            if failed_count > self.threshold:
                print(f"  [ALERT] IP: {ip:<15} -> {failed_count} failed authentication attempts!")
                suspicious_found = True
        
        if not suspicious_found:
            print("  No suspicious Brute Force activity detected. Everything looks clean.")