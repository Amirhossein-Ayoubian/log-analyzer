from collections import Counter

class LogStats:
    """
    Manages and aggregates statistical data from parsed log entries.
    """
    def __init__(self):
        self.total_requests = 0
        self.unique_ips = set()
        self.endpoint_counter = Counter()
        self.error_count = 0
        self.hourly_counter = Counter()

    def update(self, entry):
        """
        Updates the statistics based on a single successful LogEntry object.
        """
        self.total_requests += 1
        self.unique_ips.add(entry.ip)
        self.endpoint_counter[entry.endpoint] += 1
        
        if 400 <= entry.status < 600:
            self.error_count += 1

        try:
            time_part = entry.timestamp.split(':')[1]
            self.hourly_counter[time_part] += 1
        except IndexError:
            pass

    def print_report(self, total_lines, corrupted_lines):
        """
        Calculates and prints the final formatted statistical report.
        """
        error_rate = (self.error_count / self.total_requests * 100) if self.total_requests > 0 else 0.0

        print(f"\n================ ACCESS LOG ANALYSIS REPORT ================")
        print(f"Total Lines Processed:  {total_lines}")
        print(f"Corrupted Lines Skipped: {corrupted_lines}")
        print(f"Successful Requests:    {self.total_requests}")
        print(f"-------------------------------------------------------------")
        print(f"Unique IP Addresses:     {len(self.unique_ips)}")
        print(f"Total Errors (4xx/5xx):  {self.error_count} ({error_rate:.2f}%)")
        print(f"-------------------------------------------------------------")
        print(f"Top 10 Most Visited Endpoints:")
        
        for rank, (endpoint, count) in enumerate(self.endpoint_counter.most_common(10), 1):
            print(f"  {rank}. {endpoint:<30} -> {count} hits")

        print(f"-------------------------------------------------------------")
        print(f"Hourly Traffic Distribution:")
        
        for hour in sorted(self.hourly_counter.keys()):
            count = self.hourly_counter[hour]
            print(f"  {hour}:00 - {hour}:59  -> {count:<5}")
        
        print(f"=============================================================\n")