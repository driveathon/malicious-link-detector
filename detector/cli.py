import sys
import argparse
from . import scan_link

def main():
    parser = argparse.ArgumentParser(description="Malicious Link Detector CLI")
    parser.add_argument("--url", type=str, help="The URL to scan")
    parser.add_argument("--file", type=str, help="Path to a file containing URLs to scan (one per line)")
    
    args = parser.parse_args()

    if args.url:
        report = scan_link(args.url)
        print_report(report)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        report = scan_link(url)
                        print_report(report)
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found.")
    else:
        parser.print_help()

def print_report(report):
    print("-" * 40)
    print(f"URL: {report['url']}")
    print(f"Domain: {report['domain']}")
    if report['is_malicious']:
        print("Status: [SUSPICIOUS] 🚩")
        print("Reasons:")
        for reason in report['reasons']:
            print(f"  - {reason}")
    else:
        print("Status: [SAFE] ✅")
    print("-" * 40)

if __name__ == "__main__":
    main()
