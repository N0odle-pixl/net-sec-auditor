# Net-Sec-Auditor 🛡️

A modular command-line interface (CLI) security auditing and log analysis tool written in Python. Designed for automated reconnaissance, infrastructure integrity checks, and brute-force/credential stuffing attack detection.

## Features

* **SSL/TLS Certificate Inspection:** Analyzes cryptographic strength, cipher suites, expiration timelines, and validity.
* **DNS Security Records Audit:** Verifies critical email and domain protection records (`SPF`, `DMARC`, `DKIM`).
* **File Integrity Monitoring:** Computes cryptographic SHA-256 hashes for binary or source file verification.
* **Log Analysis & Threat Detection:** Parses `auth.log` (SSH) and Nginx logs using optimized Regular Expressions (`re`) to identify Brute-Force and Credential Stuffing activities based on adjustable thresholds.
* **Flexible Reporting:** Outputs structured results directly to the terminal or exports them into JSON/Markdown files.

## Project Structure

```text
net-sec-auditor/
│
├── main.py                 # CLI entry point (argparse integration)
├── modules/
│   ├── __init__.py
│   ├── ssl_checker.py      # SSL/TLS inspection module
│   ├── dns_checker.py      # DNS record verification (dnspython)
│   ├── hasher.py           # SHA-256 file hashing utility
│   └── log_parser.py       # Log parsing & brute-force detection
└── README.md