from collections import Counter

class SecurityDetector:
    """
    Analyzes parsed log entries to detect security anomalies, malicious activities,
    and server-side error spikes.
    """
    def __init__(self, auth_threshold=5, error_spike_threshold=5.0):
        self.auth_threshold = auth_threshold
        self.error_spike_threshold = error_spike_threshold
        
        self.failed_login_counter = Counter()
        
        self.hourly_5xx_counter = Counter()
        self.hourly_total_counter = Counter()

    def inspect(self, entry):
        """
        Inspects a single log entry for suspicious behavior and server errors.
        """
        if entry.status in (401, 403):
            self.failed_login_counter[entry.ip] += 1

        try:
            hour = entry.timestamp.split(':')[1]
            self.hourly_total_counter[hour] += 1
            
            if 500 <= entry.status < 600:
                self.hourly_5xx_counter[hour] += 1
        except IndexError:
            pass

    def print_alerts(self):
        """
        Prints colorized, high-visibility security alerts and infrastructure anomalies.
        """
        BLUE = "\033[94m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RED = "\033[91m"
        RESET = "\033[0m"
        BOLD = "\033[1m"
        DIM = "\033[2m"

        print(f"{YELLOW}{BOLD}🚨 Security Monitoring - Brute Force Detection{RESET} {DIM}(Threshold: > {self.auth_threshold} failures){RESET}")
        
        suspicious_found = False
        for ip, failed_count in self.failed_login_counter.items():
            if failed_count > self.auth_threshold:
                print(f"  {RED}{BOLD}[ALERT]{RESET} IP: {BOLD}{ip:<15}{RESET} -> {RED}{BOLD}{failed_count:<3}{RESET} failed auth attempts!")
                suspicious_found = True
        
        if not suspicious_found:
            print(f"  {GREEN}✔ No suspicious Brute Force activity detected.{RESET}")
            
        print(f"{BLUE}-------------------------------------------------------------{RESET}")
        
        print(f"{RED}{BOLD}⚠️ Anomaly Detection - Automated 5xx Error Spikes{RESET} {DIM}(Threshold: > {self.error_spike_threshold}%){RESET}")
        
        spike_found = False
        for hour in sorted(self.hourly_total_counter.keys()):
            total_hourly = self.hourly_total_counter[hour]
            errors_hourly = self.hourly_5xx_counter[hour]
            
            hourly_error_rate = (errors_hourly / total_hourly * 100) if total_hourly > 0 else 0.0
            
            if hourly_error_rate > self.error_spike_threshold:
                print(f"  {RED}{BOLD}[CRITICAL]{RESET} Hour {hour}:00-{hour}:59 -> Error Rate: {RED}{BOLD}{hourly_error_rate:.2f}%{RESET} ({errors_hourly}/{total_hourly} requests failed)")
                spike_found = True
                
        if not spike_found:
            print(f"  {GREEN}✔ No server error spikes detected. Infrastructure is stable.{RESET}")

        print(f"{BLUE}============================================================={RESET}")

    def to_dict(self):
        """
        Returns security alerts as a clean dictionary for JSON export.
        """
        brute_force_alerts = []
        for ip, failed_count in self.failed_login_counter.items():
            if failed_count > self.auth_threshold:
                brute_force_alerts.append({"ip": ip, "failed_attempts": failed_count})

        error_spikes = []
        for hour in sorted(self.hourly_total_counter.keys()):
            total = self.hourly_total_counter[hour]
            errors = self.hourly_5xx_counter[hour]
            rate = (errors / total * 100) if total > 0 else 0.0
            if rate > self.error_spike_threshold:
                error_spikes.append({"hour": f"{hour}:00-{hour}:59", "error_rate_percentage": round(rate, 2), "failed_requests": errors})

        return {
            "brute_force_alerts": brute_force_alerts,
            "server_error_spikes": error_spikes
        }