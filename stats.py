from collections import Counter
import matplotlib.pyplot as plt

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

    def print_report(self, total_lines, corrupted_lines, top_n=10):
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
        print(f"Top {top_n} Most Visited Endpoints:")
        
        for rank, (endpoint, count) in enumerate(self.endpoint_counter.most_common(top_n), 1):
            print(f"  {rank:<2}. {endpoint:<30} -> {count} hits")

        print(f"-------------------------------------------------------------")
        print(f"Hourly Traffic Distribution:")
        
        for hour in sorted(hours := [f"{h:02d}" for h in range(24)]):
            count = self.hourly_counter[hour]
            if count > 0:
                print(f"  {hour}:00 - {hour}:59  -> {count:<5} requests")
        
        self._generate_hourly_chart()
        
        print(f"=============================================================\n")

    def _generate_hourly_chart(self):
        """
        Generates and saves a histogram chart of hourly traffic distribution.
        """
        hours = [f"{h:02d}" for h in range(24)]
        counts = [self.hourly_counter[h] for h in hours]

        plt.figure(figsize=(12, 6))
        plt.bar(hours, counts, color='royalblue', edgecolor='black', alpha=0.7)
        
        plt.title('Hourly Traffic Distribution', fontsize=14, fontweight='bold')
        plt.xlabel('Hour of the Day (00 - 23)', fontsize=12)
        plt.ylabel('Number of Requests', fontsize=12)
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        chart_filename = 'hourly_traffic.png'
        plt.savefig(chart_filename, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"Success: Hourly traffic chart saved as '{chart_filename}'")

    def to_dict(self, top_n=10):
        """
        Returns the statistical data as a clean dictionary for JSON export.
        """
        hours = [f"{h:02d}" for h in range(24)]
        return {
            "total_requests": self.total_requests,
            "unique_ips_count": len(self.unique_ips),
            "error_count": self.error_count,
            "top_endpoints": [{"endpoint": ep, "hits": count} for ep, count in self.endpoint_counter.most_common(top_n)],
            "hourly_traffic": {h: self.hourly_counter[h] for h in hours if self.hourly_counter[h] > 0}
        }