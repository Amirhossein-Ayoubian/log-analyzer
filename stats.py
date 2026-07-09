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

    def print_report(self, total_lines, corrupted_lines, filtered_out_lines, top_n=10,
                     start_hour=None, end_hour=None):
        """
        Calculates and prints a professionally styled, colorized statistical report.
        """
        error_rate = (self.error_count / self.total_requests * 100) if self.total_requests > 0 else 0.0

        BLUE = "\033[94m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RED = "\033[91m"
        CYAN = "\033[96m"
        RESET = "\033[0m"
        BOLD = "\033[1m"
        DIM = "\033[2m"

        time_window = f"{start_hour:02d}:00 - {end_hour:02d}:59" if start_hour is not None and end_hour is not None else "All Hours"

        print(f"\n{BLUE}{BOLD}============================================================={RESET}")
        print(f"{BLUE}{BOLD}                ACCESS LOG ANALYSIS REPORT                   {RESET}")
        print(f"{BLUE}{BOLD}============================================================={RESET}")
        
        print(f"{BOLD}✔ File Processing Summary:{RESET}")
        print(f"  • Total Lines Processed:   {BOLD}{total_lines:<10}{RESET}")
        print(f"  • Corrupted Lines Skipped: {RED if corrupted_lines > 0 else GREEN}{corrupted_lines:<10}{RESET}{DIM}(Malformed regex rows){RESET}")
        print(f"  • Time-Filtered Out:       {YELLOW if filtered_out_lines > 0 else GREEN}{filtered_out_lines:<10}{RESET}{DIM}(Outside active window){RESET}")
        print(f"  • Active Time Window:      {CYAN}{time_window}{RESET}")
        print(f"  • Successful Requests:     {GREEN}{BOLD}{self.total_requests:<10}{RESET}{DIM}(Analyzed traffic){RESET}")
        print(f"{BLUE}-------------------------------------------------------------{RESET}")
        
        print(f"{BOLD}📊 Core Metrics:{RESET}")
        print(f"  • Unique IP Addresses:     {YELLOW}{BOLD}{len(self.unique_ips):<10}{RESET}")
        print(f"  • Total Errors (4xx/5xx):  {RED if self.error_count > 0 else GREEN}{BOLD}{self.error_count:<10}{RESET}{RED if self.error_count > 0 else GREEN}({error_rate:.2f}%){RESET}")
        print(f"{BLUE}-------------------------------------------------------------{RESET}")
        
        print(f"{BOLD}🔥 Top {top_n} Most Visited Endpoints:{RESET}")
        if self.endpoint_counter:
            for rank, (endpoint, count) in enumerate(self.endpoint_counter.most_common(top_n), 1):
                print(f"  {CYAN}{rank:<2}{RESET}. {endpoint:<35} -> {GREEN}{count:<6}{RESET} hits")
        else:
            print(f"  {DIM}No endpoint hits found in this active window.{RESET}")
            
        print(f"{BLUE}-------------------------------------------------------------{RESET}")
        
        print(f"{BOLD}🕒 Hourly Traffic Distribution (Text Summary):{RESET}")
        active_hours = 0
        for hour in sorted([f"{h:02d}" for h in range(24)]):
            count = self.hourly_counter[hour]
            if count > 0:
                active_hours += 1
                print(f"  • {hour}:00 - {hour}:59  -> {YELLOW}{count:<6}{RESET} requests")
                
        if active_hours == 0:
            print(f"  {DIM}No requests captured for the active hours.{RESET}")
            
        print(f"{BLUE}-------------------------------------------------------------{RESET}")
        
        self._generate_hourly_chart()

        print(f"{BLUE}-------------------------------------------------------------{RESET}")

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