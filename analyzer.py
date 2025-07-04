#!/usr/bin/env python3
"""
NetTrafficAnalyzer - Core analysis module
Analyzes network traffic from PCAP files and detects anomalies
"""

import argparse
import csv
import json
import os
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List, Any, Tuple

import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
import numpy as np


class NetworkTrafficAnalyzer:
    """Main class for analyzing network traffic and detecting anomalies"""
    
    def __init__(self):
        self.packets = []
        self.analysis_results = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'anomalies': [],
            'dns_queries': [],
            'http_requests': [],
            'port_activity': defaultdict(int),
            'ip_conversations': defaultdict(int),
            'packet_sizes': [],
            'timestamps': []
        }
        
        # Anomaly detection thresholds
        self.thresholds = {
            'unusual_ports': [22, 23, 3389, 4444, 5555],  # Common attack ports
            'max_dns_ttl': 86400,  # 24 hours
            'min_dns_ttl': 60,     # 1 minute
            'large_packet_threshold': 1500,  # MTU size
            'suspicious_user_agents': ['sqlmap', 'nmap', 'nikto', 'dirb'],
            'max_connections_per_ip': 100
        }
    
    def load_pcap(self, pcap_file: str) -> bool:
        """Load and parse PCAP file"""
        try:
            print(f"Loading PCAP file: {pcap_file}")
            self.packets = rdpcap(pcap_file)
            self.analysis_results['total_packets'] = len(self.packets)
            print(f"Successfully loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"Error loading PCAP file: {e}")
            return False
    
    def analyze_protocols(self):
        """Analyze protocol distribution"""
        for packet in self.packets:
            if IP in packet:
                if TCP in packet:
                    self.analysis_results['protocols']['TCP'] += 1
                elif UDP in packet:
                    self.analysis_results['protocols']['UDP'] += 1
                elif packet[IP].proto == 1:  # ICMP
                    self.analysis_results['protocols']['ICMP'] += 1
                else:
                    self.analysis_results['protocols']['Other'] += 1
    
    def analyze_dns_traffic(self):
        """Analyze DNS queries and detect anomalies"""
        dns_count = 0
        anomalies = []
        
        for packet in self.packets:
            if DNS in packet and packet[DNS].qr == 0:  # DNS query
                dns_count += 1
                query_name = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                
                self.analysis_results['dns_queries'].append({
                    'query': query_name,
                    'timestamp': packet.time,
                    'src_ip': packet[IP].src if IP in packet else 'Unknown'
                })
                
                # Check for suspicious DNS queries
                if len(query_name) > 50:  # Unusually long domain
                    anomalies.append({
                        'type': 'Suspicious DNS Query',
                        'description': f'Unusually long domain name: {query_name[:50]}...',
                        'timestamp': packet.time,
                        'src_ip': packet[IP].src if IP in packet else 'Unknown'
                    })
                
                # Check for DGA-like domains (many numbers)
                if sum(c.isdigit() for c in query_name) > len(query_name) * 0.3:
                    anomalies.append({
                        'type': 'Potential DGA Domain',
                        'description': f'Domain with high number ratio: {query_name}',
                        'timestamp': packet.time,
                        'src_ip': packet[IP].src if IP in packet else 'Unknown'
                    })
        
        self.analysis_results['anomalies'].extend(anomalies)
        return dns_count, len(anomalies)
    
    def analyze_http_traffic(self):
        """Analyze HTTP traffic and detect suspicious patterns"""
        http_requests = 0
        anomalies = []
        
        for packet in self.packets:
            if HTTPRequest in packet:
                http_requests += 1
                http_layer = packet[HTTPRequest]
                
                request_info = {
                    'method': http_layer.Method.decode() if http_layer.Method else 'Unknown',
                    'host': http_layer.Host.decode() if http_layer.Host else 'Unknown',
                    'path': http_layer.Path.decode() if http_layer.Path else 'Unknown',
                    'user_agent': http_layer.User_Agent.decode() if http_layer.User_Agent else 'Unknown',
                    'timestamp': packet.time,
                    'src_ip': packet[IP].src if IP in packet else 'Unknown'
                }
                
                self.analysis_results['http_requests'].append(request_info)
                
                # Check for suspicious user agents
                user_agent = request_info['user_agent'].lower()
                for suspicious_ua in self.thresholds['suspicious_user_agents']:
                    if suspicious_ua in user_agent:
                        anomalies.append({
                            'type': 'Suspicious User Agent',
                            'description': f'Potential security tool detected: {request_info["user_agent"]}',
                            'timestamp': packet.time,
                            'src_ip': request_info['src_ip']
                        })
                
                # Check for SQL injection patterns
                path = request_info['path'].lower()
                sql_patterns = ['union select', 'drop table', '1=1', 'or 1=1', 'script>alert']
                for pattern in sql_patterns:
                    if pattern in path:
                        anomalies.append({
                            'type': 'Potential SQL Injection',
                            'description': f'Suspicious pattern in URL: {pattern}',
                            'timestamp': packet.time,
                            'src_ip': request_info['src_ip']
                        })
        
        self.analysis_results['anomalies'].extend(anomalies)
        return http_requests
    
    def analyze_port_activity(self):
        """Analyze port usage and detect unusual activity"""
        port_counts = defaultdict(int)
        anomalies = []
        
        for packet in self.packets:
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                port_counts[dst_port] += 1
                self.analysis_results['port_activity'][dst_port] += 1
                
                # Check for connections to unusual ports
                if dst_port in self.thresholds['unusual_ports']:
                    anomalies.append({
                        'type': 'Unusual Port Activity',
                        'description': f'Connection to suspicious port {dst_port}',
                        'timestamp': packet.time,
                        'src_ip': packet[IP].src if IP in packet else 'Unknown',
                        'dst_ip': packet[IP].dst if IP in packet else 'Unknown'
                    })
        
        self.analysis_results['anomalies'].extend(anomalies)
        return port_counts
    
    def analyze_ip_conversations(self):
        """Analyze IP conversations and detect potential data exfiltration"""
        conversations = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        anomalies = []
        
        for packet in self.packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                conversation = f"{src_ip} -> {dst_ip}"
                
                conversations[conversation]['packets'] += 1
                conversations[conversation]['bytes'] += len(packet)
                
                self.analysis_results['ip_conversations'][conversation] += 1
        
        # Detect potential data exfiltration (high volume conversations)
        for conversation, stats in conversations.items():
            if stats['bytes'] > 1000000:  # More than 1MB
                anomalies.append({
                    'type': 'Potential Data Exfiltration',
                    'description': f'High volume conversation: {conversation} ({stats["bytes"]} bytes)',
                    'timestamp': datetime.now().timestamp(),
                    'conversation': conversation
                })
        
        self.analysis_results['anomalies'].extend(anomalies)
        return conversations
    
    def analyze_packet_sizes(self):
        """Analyze packet size distribution"""
        sizes = []
        anomalies = []
        
        for packet in self.packets:
            size = len(packet)
            sizes.append(size)
            self.analysis_results['packet_sizes'].append(size)
            self.analysis_results['timestamps'].append(packet.time)
            
            # Check for unusually large packets
            if size > self.thresholds['large_packet_threshold']:
                anomalies.append({
                    'type': 'Large Packet',
                    'description': f'Unusually large packet: {size} bytes',
                    'timestamp': packet.time,
                    'src_ip': packet[IP].src if IP in packet else 'Unknown'
                })
        
        self.analysis_results['anomalies'].extend(anomalies)
        return sizes
    
    def run_full_analysis(self) -> Dict[str, Any]:
        """Run complete traffic analysis"""
        print("Starting comprehensive network traffic analysis...")
        
        # Run all analysis modules
        self.analyze_protocols()
        dns_count, dns_anomalies = self.analyze_dns_traffic()
        http_count = self.analyze_http_traffic()
        port_activity = self.analyze_port_activity()
        conversations = self.analyze_ip_conversations()
        packet_sizes = self.analyze_packet_sizes()
        
        # Generate summary statistics
        summary = {
            'total_packets': self.analysis_results['total_packets'],
            'dns_queries': dns_count,
            'http_requests': http_count,
            'total_anomalies': len(self.analysis_results['anomalies']),
            'protocol_distribution': dict(self.analysis_results['protocols']),
            'top_ports': dict(Counter(self.analysis_results['port_activity']).most_common(10)),
            'avg_packet_size': np.mean(self.analysis_results['packet_sizes']) if self.analysis_results['packet_sizes'] else 0,
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        print(f"Analysis complete! Found {len(self.analysis_results['anomalies'])} anomalies")
        return {
            'summary': summary,
            'detailed_results': self.analysis_results
        }
    
    def export_csv_report(self, output_file: str):
        """Export analysis results to CSV format"""
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write summary
                writer.writerow(['NETWORK TRAFFIC ANALYSIS REPORT'])
                writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
                writer.writerow([])
                
                # Write summary statistics
                writer.writerow(['SUMMARY STATISTICS'])
                writer.writerow(['Total Packets:', self.analysis_results['total_packets']])
                writer.writerow(['DNS Queries:', len(self.analysis_results['dns_queries'])])
                writer.writerow(['HTTP Requests:', len(self.analysis_results['http_requests'])])
                writer.writerow(['Total Anomalies:', len(self.analysis_results['anomalies'])])
                writer.writerow([])
                
                # Write anomalies
                writer.writerow(['DETECTED ANOMALIES'])
                writer.writerow(['Type', 'Description', 'Timestamp', 'Source IP'])
                for anomaly in self.analysis_results['anomalies']:
                    writer.writerow([
                        anomaly.get('type', ''),
                        anomaly.get('description', ''),
                        datetime.fromtimestamp(anomaly.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                        anomaly.get('src_ip', '')
                    ])
                
            print(f"CSV report exported to: {output_file}")
            return True
        except Exception as e:
            print(f"Error exporting CSV report: {e}")
            return False
    
    def export_json_report(self, output_file: str):
        """Export analysis results to JSON format"""
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Convert defaultdicts to regular dicts for JSON serialization
            json_data = {
                'summary': {
                    'total_packets': self.analysis_results['total_packets'],
                    'dns_queries': len(self.analysis_results['dns_queries']),
                    'http_requests': len(self.analysis_results['http_requests']),
                    'total_anomalies': len(self.analysis_results['anomalies']),
                    'protocol_distribution': dict(self.analysis_results['protocols']),
                    'analysis_timestamp': datetime.now().isoformat()
                },
                'anomalies': self.analysis_results['anomalies'],
                'dns_queries': self.analysis_results['dns_queries'][:100],  # Limit for file size
                'http_requests': self.analysis_results['http_requests'][:100],
                'top_ports': dict(Counter(self.analysis_results['port_activity']).most_common(20))
            }
            
            with open(output_file, 'w') as jsonfile:
                json.dump(json_data, jsonfile, indent=2, default=str)
            
            print(f"JSON report exported to: {output_file}")
            return True
        except Exception as e:
            print(f"Error exporting JSON report: {e}")
            return False


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(description='NetTrafficAnalyzer - Analyze network traffic and detect anomalies')
    parser.add_argument('--pcap', required=True, help='Path to PCAP file')
    parser.add_argument('--output', help='Output file path (CSV format)')
    parser.add_argument('--json-output', help='JSON output file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = NetworkTrafficAnalyzer()
    
    # Load PCAP file
    if not analyzer.load_pcap(args.pcap):
        print("Failed to load PCAP file")
        return 1
    
    # Run analysis
    results = analyzer.run_full_analysis()
    
    # Display summary
    summary = results['summary']
    print("\n" + "="*50)
    print("NETWORK TRAFFIC ANALYSIS SUMMARY")
    print("="*50)
    print(f"Total Packets: {summary['total_packets']}")
    print(f"DNS Queries: {summary['dns_queries']}")
    print(f"HTTP Requests: {summary['http_requests']}")
    print(f"Anomalies Detected: {summary['total_anomalies']}")
    print(f"Average Packet Size: {summary['avg_packet_size']:.2f} bytes")
    
    if args.verbose and analyzer.analysis_results['anomalies']:
        print("\nDETECTED ANOMALIES:")
        for i, anomaly in enumerate(analyzer.analysis_results['anomalies'][:10], 1):
            print(f"{i}. {anomaly['type']}: {anomaly['description']}")
    
    # Export reports
    if args.output:
        analyzer.export_csv_report(args.output)
    
    if args.json_output:
        analyzer.export_json_report(args.json_output)
    
    # Default CSV export if no output specified
    if not args.output and not args.json_output:
        default_output = "reports/traffic_analysis_report.csv"
        analyzer.export_csv_report(default_output)
    
    print("\nAnalysis completed successfully!")
    return 0


if __name__ == "__main__":
    exit(main())