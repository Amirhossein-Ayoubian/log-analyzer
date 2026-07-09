import argparse
import os
import sys

from models import LogEntry
from stats import LogStats

def process_log_file(file_path):
    """
    Reads the log file line by line to process data.
    """
    total_lines = 0
    corrupted_lines = 0

    stats = LogStats()
    
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            total_lines += 1
            
            entry = LogEntry.parse_line(line.strip())
            
            if entry is None:
                corrupted_lines += 1
                continue
            
            stats.update(entry)

            successful_count = total_lines - corrupted_lines
            if successful_count <= 5:
                entry.print_details(successful_count)
                
    stats.print_report(total_lines, corrupted_lines)

def main():
    parser = argparse.ArgumentParser(
        description="CLI tool for analyzing and extracting insights from web server access logs."
    )
    
    parser.add_argument(
        'log_file', 
        type=str, 
        help="Path to the access log file that needs to be processed."
    )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.log_file):
        print(f"Error: The file '{args.log_file}' does not exist.", file=sys.stderr)
        sys.exit(1)
        
    print(f"Success: File found! Preparing to process: {args.log_file}")
    process_log_file(args.log_file)

if __name__ == "__main__":
    main()