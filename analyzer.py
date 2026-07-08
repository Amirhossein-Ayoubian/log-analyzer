import argparse
import os
import sys

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

if __name__ == "__main__":
    main()