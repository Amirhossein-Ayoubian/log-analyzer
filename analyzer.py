import argparse
import os
import sys
import gzip
import json

from models import LogEntry
from stats import LogStats
from security import SecurityDetector

def process_log_file(file_path, output_json):
    """
    Reads the log file line by line to process data.
    """
    total_lines = 0
    corrupted_lines = 0

    stats = LogStats()
    detector = SecurityDetector(auth_threshold=5, error_spike_threshold=5.0)

    is_gzip = file_path.endswith('.gz')
    opener = gzip.open if is_gzip else open
    mode = 'rt' if is_gzip else 'r'
    print(f"Opening file using {'Gzip Stream' if is_gzip else 'Standard Stream'}...")
    
    with opener(file_path, mode, encoding='utf-8') as file:
        for line in file:
            total_lines += 1
            
            entry = LogEntry.parse_line(line.strip())
            
            if entry is None:
                corrupted_lines += 1
                continue
            
            stats.update(entry)
            detector.inspect(entry)
                
    stats.print_report(total_lines, corrupted_lines)
    detector.print_alerts()

    if output_json:
        save_json(file_path, total_lines, corrupted_lines, stats, detector, output_json)

def main():
    parser = argparse.ArgumentParser(
        description="CLI tool for analyzing and extracting insights from web server access logs."
    )
    
    parser.add_argument(
        'log_file', 
        type=str, 
        help="Path to the access log file that needs to be processed."
    )

    parser.add_argument(
        '--json', type=str, metavar='OUTPUT_FILE.json',
        help="Path to save the analyzed report in structured JSON format."
    )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.log_file):
        print(f"Error: The file '{args.log_file}' does not exist.", file=sys.stderr)
        sys.exit(1)
        
    print(f"Success: File found! Preparing to process: {args.log_file}")
    process_log_file(args.log_file, args.json)

def save_json(file_path, total_lines, corrupted_lines, stats, detector, output_json):
    combined_report = {
        "metadata": {
            "file_processed": file_path,
            "total_lines": total_lines,
            "corrupted_lines_skipped": corrupted_lines,
        },
        "analytics": stats.to_dict(),
        "security_anomalies": detector.to_dict()
    }
    
    with open(output_json, 'w', encoding='utf-8') as json_file:
        json.dump(combined_report, json_file, indent=4, ensure_ascii=False)
    print(f"Success: Structured JSON report saved to '{output_json}'")

if __name__ == "__main__":
    main()