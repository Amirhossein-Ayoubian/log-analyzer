import argparse
import os
import sys
import gzip
import json

from models import LogEntry
from stats import LogStats
from security import SecurityDetector

def process_log_file(file_path, top_n, output_json, start_hour, end_hour):
    """
    Reads the log file line by line to process data.
    """
    total_lines = 0
    corrupted_lines = 0
    filtered_out_lines = 0

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
            
            try:
                log_hour = int(entry.timestamp.split(':')[1])
                
                if start_hour is not None and log_hour < start_hour:
                    filtered_out_lines += 1
                    continue
                
                if end_hour is not None and log_hour > end_hour:
                    filtered_out_lines += 1
                    continue
            except (IndexError, ValueError):
                pass

            stats.update(entry)
            detector.inspect(entry)
                
    stats.print_report(total_lines, corrupted_lines, filtered_out_lines, top_n=top_n, 
                       start_hour=start_hour, end_hour=end_hour)
    detector.print_alerts()

    if output_json:
        save_json(file_path, total_lines, corrupted_lines, stats, detector, output_json, top_n,
                  filtered_out_lines, start_hour, end_hour)

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
        '--top', type=int, default=10, 
        help="Specify the number of top visited endpoints to display (Default: 10)."
    )

    parser.add_argument(
        '--json', type=str, metavar='OUTPUT_FILE.json',
        help="Path to save the analyzed report in structured JSON format."
    )

    parser.add_argument(
        '--start', type=int, choices=range(0, 24), default=0, 
        help="Start hour filter (0-23)."
    )

    parser.add_argument(
        '--end', type=int, choices=range(0, 24), default=23,
        help="End hour filter (0-23)."
        )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.log_file):
        print(f"Error: The file '{args.log_file}' does not exist.", file=sys.stderr)
        sys.exit(1)
        
    print(f"\nSuccess: File found! Preparing to process: {args.log_file}")
    process_log_file(
        args.log_file, top_n=args.top, output_json=args.json, 
        start_hour=args.start, end_hour=args.end
    )

def save_json(file_path, total_lines, corrupted_lines, stats, detector, output_json, top_n, 
              filtered_out_lines, start_hour, end_hour):
    combined_report = {
        "metadata": {
            "file_processed": file_path,
            "total_lines": total_lines,
            "corrupted_lines_skipped": corrupted_lines,
            "lines_filtered_out_by_time": filtered_out_lines,
            "start_hour": str(start_hour) + ":00",
            "end_hour": str(end_hour) + ":59",
        },
        "analytics": stats.to_dict(top_n=top_n),
        "security_anomalies": detector.to_dict()
    }
    
    os.makedirs("reports", exist_ok=True)

    json_filename = os.path.basename(output_json)
    report_path = os.path.join("reports", json_filename)

    with open(report_path, 'w', encoding='utf-8') as json_file:
        json.dump(combined_report, json_file, indent=4, ensure_ascii=False)
    print(f"\nSuccess: Structured JSON report saved to '{report_path}'\n")

if __name__ == "__main__":
    main()