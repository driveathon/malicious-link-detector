import sys
import argparse
import asyncio
import os
from . import scan_link, scan_links_async

def main():
    parser = argparse.ArgumentParser(description="Advanced Malicious Link Detector CLI")
    parser.add_argument("--url", type=str, help="The URL to scan")
    parser.add_argument("--file", type=str, help="Path to a file containing URLs to scan")
    parser.add_argument("--no-redirects", action="store_true", help="Skip redirect tracing")
    parser.add_argument("--no-whois", action="store_true", help="Skip WHOIS domain age check")
    parser.add_argument("--no-intel", action="store_true", help="Skip external threat intel APIs")
    parser.add_argument("--no-ssl", action="store_true", help="Skip SSL/TLS validation")
    parser.add_argument("--no-visual", action="store_true", help="Skip visual screenshot analysis")
    
    args = parser.parse_args()

    # Pass flags to scan_link/scan_links_async
    scan_args = {
        "trace_redirects": not args.no_redirects,
        "check_whois": not args.no_whois,
        "check_intel": not args.no_intel,
        "check_ssl": not args.no_ssl,
        "check_visual": not args.no_visual
    }

    if args.url:
        report = scan_link(args.url, **scan_args)
        print_report(report)
    elif args.file:
        asyncio.run(scan_file_async(args.file, **scan_args))
    else:
        parser.print_help()

async def scan_file_async(file_path, **kwargs):
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("No URLs found in file.")
            return

        print(f"🧐 Scanning {len(urls)} URLs...")
        results = await scan_links_async(urls, **kwargs)
        
        for result in results:
            if isinstance(result, tuple):
                report, cached = result
                print_report(report, cached)
            else:
                print_report(result)
            
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")

def print_report(report, cached=False):
    print("-" * 40)
    cache_tag = " [CACHED]" if cached else ""
    print(f"URL: {report['url']}{cache_tag}")
    if report.get('final_url') and report['final_url'] != report['url']:
        print(f"Final URL: {report['final_url']}")
    
    domain = report.get('domain')
    if domain:
        print(f"Domain: {domain}")
        
    if report.get('whois'):
        age = report['whois'].get('age_days')
        if age is not None:
            print(f"Domain Age: {age} days")

    if report.get('ssl'):
        issuer = report['ssl'].get('issuer')
        if issuer:
            print(f"SSL Issuer: {issuer}")
        if not report['ssl'].get('has_https'):
             print("SSL: [NONE/INSECURE] ⚠️")

    if report.get('screenshot_path'):
        print(f"Screenshot saved to: {report['screenshot_path']}")

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
