import argparse
import json
import sys
from modules.ssl_checker import check_ssl
from modules.dns_checker import check_dns
from modules.hasher import calculate_sha256
from modules.log_parser import LogParser

def main():
    parser = argparse.ArgumentParser(description="Net-Sec-Auditor: Python CLI Security & Audit Tool")
    parser.add_argument("--domain", help="Target domain for SSL and DNS security audit")
    parser.add_argument("--file", help="File path to calculate SHA-256 integrity hash")
    parser.add_argument("--logfile", help="Path to log file (auth.log or nginx log) for attack detection")
    parser.add_argument("--logtype", choices=['auth', 'nginx'], default='auth', help="Type of log file being parsed")
    parser.add_argument("--threshold", type=int, default=5, help="Failure threshold for brute-force/credential stuffing alerts")
    parser.add_argument("--output", help="Path to save audit report (.json or .md)")

    args = parser.parse_args()
    report = {}

    if args.domain:
        print(f"[*] Running SSL and DNS audit for: {args.domain}")
        report["ssl"] = check_ssl(args.domain)
        report["dns"] = check_dns(args.domain)

    if args.file:
        print(f"[*] Calculating SHA-256 hash for file: {args.file}")
        report["hasher"] = calculate_sha256(args.file)

    if args.logfile:
        print(f"[*] Parsing log file ({args.logtype}): {args.logfile}")
        parser_obj = LogParser(threshold=args.threshold)
        parser_obj.analyze_logs(args.logfile, log_type=args.logtype)
        report["log_analysis"] = parser_obj.detect_attacks()

    if not report:
        parser.print_help()
        sys.exit(1)

    # Output handling
    output_data = json.dumps(report, indent=4)
    print("\n[+] Audit Results:")
    print(output_data)

    if args.output:
        if args.output.endswith(".md"):
            md_content = f"# Security Audit Report\n\n```json\n{output_data}\n```\n"
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(md_content)
            print(f"[+] Report saved successfully as Markdown to {args.output}")
        else:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_data)
            print(f"[+] Report saved successfully as JSON to {args.output}")

if __name__ == "__main__":
    main()