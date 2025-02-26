# NetTrafficAnalyzer
A Python-based toolset for analyzing network traffic, detecting anomalies, and securing protocols.

## Features
- Parses TCP/IP, DNS, and HTTP packets from PCAP files
- Flags suspicious patterns (e.g., unusual port activity, data exfiltration)
- Exports detailed reports in CSV and JSON formats

## Tech Stack
- Python 3.9, scapy, pyshark
- Wireshark (used for validation during dev)

## Setup
1. Clone the repo:  git clone https://github.com/ravitejaannam-008/NetTrafficAnalyzer.git cd NetTrafficAnalyzer
2. Install dependencies: pip install -r requirements.txt
3. Ensure Wireshark is installed (optional for PCAP generation).
4. ## Usage
Analyze a PCAP file: python analyze.py --pcap captures/sample.pcap --output reports/traffic_report.csv
- Input: `captures/sample.pcap` (sample included)
- Output: `reports/traffic_report.csv` (anomalies flagged)

## Example

$ python analyze.py --pcap captures/sample.pcap Detected: 15 DNS queries, 2 anomalies (unusual TTL) 
Report saved to reports/traffic_report.csv

## Why This Matters
Built from my Junior Network Engineer role at Indian Railways, where I used Wireshark to spot data exfiltration—now automated for efficiency.
