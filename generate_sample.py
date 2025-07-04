#!/usr/bin/env python3
"""
Sample PCAP Generator for NetTrafficAnalyzer
Generates synthetic network traffic data for testing purposes
"""

import os
import random
import time
from datetime import datetime, timedelta

try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest
except ImportError:
    print("Scapy not installed. Please install with: pip install scapy")
    exit(1)


def generate_dns_traffic(packets, count=50):
    """Generate DNS query packets"""
    domains = [
        "google.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "netflix.com", "youtube.com", "twitter.com",
        "instagram.com", "linkedin.com", "github.com", "stackoverflow.com",
        # Some suspicious looking domains
        "3x4mpl3-susp1c10us-d0ma1n.com",
        "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.malicious.net",
        "12345.67890.suspicious.org"
    ]
    
    src_ips = ["192.168.1.10", "192.168.1.15", "10.0.0.5", "172.16.0.100"]
    dns_server = "8.8.8.8"
    
    print(f"Generating {count} DNS packets...")
    
    for i in range(count):
        src_ip = random.choice(src_ips)
        domain = random.choice(domains)
        
        # Create DNS query
        dns_query = IP(src=src_ip, dst=dns_server) / \
                   UDP(sport=random.randint(32768, 65535), dport=53) / \
                   DNS(rd=1, qd=DNSQR(qname=domain))
        
        packets.append(dns_query)
        
        # Sometimes add a response
        if random.random() > 0.3:
            dns_response = IP(src=dns_server, dst=src_ip) / \
                          UDP(sport=53, dport=dns_query[UDP].sport) / \
                          DNS(id=dns_query[DNS].id, qr=1, aa=0, rcode=0,
                              qd=dns_query[DNS].qd,
                              an=DNSRR(rrname=domain, ttl=random.randint(60, 86400),
                                      rdata="93.184.216.34"))
            packets.append(dns_response)


def generate_http_traffic(packets, count=30):
    """Generate HTTP request packets"""
    websites = [
        ("google.com", "/search?q=network+security"),
        ("github.com", "/security/advisories"),
        ("stackoverflow.com", "/questions/tagged/networking"),
        ("amazon.com", "/products/cybersecurity"),
        # Suspicious requests
        ("vulnerable-site.com", "/admin.php?id=1' OR 1=1--"),
        ("target.com", "/search.php?q=<script>alert('xss')</script>"),
        ("webapp.com", "/login.php?user=admin&pass=123456")
    ]
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "curl/7.68.0",
        "sqlmap/1.4.2 (http://sqlmap.org)",  # Suspicious
        "Nmap Scripting Engine",  # Suspicious
    ]
    
    src_ips = ["192.168.1.10", "192.168.1.15", "10.0.0.5"]
    
    print(f"Generating {count} HTTP packets...")
    
    for i in range(count):
        src_ip = random.choice(src_ips)
        dst_ip = f"93.184.216.{random.randint(1, 100)}"
        website, path = random.choice(websites)
        user_agent = random.choice(user_agents)
        
        # Create HTTP request
        http_request = IP(src=src_ip, dst=dst_ip) / \
                      TCP(sport=random.randint(32768, 65535), dport=80) / \
                      f"GET {path} HTTP/1.1\r\n" \
                      f"Host: {website}\r\n" \
                      f"User-Agent: {user_agent}\r\n" \
                      f"Accept: text/html,application/xhtml+xml\r\n" \
                      f"Connection: keep-alive\r\n\r\n"
        
        packets.append(http_request)


def generate_tcp_traffic(packets, count=40):
    """Generate various TCP traffic including suspicious ports"""
    src_ips = ["192.168.1.10", "192.168.1.15", "10.0.0.5", "172.16.0.100"]
    dst_ips = ["203.0.113.10", "198.51.100.5", "93.184.216.34"]
    
    # Mix of normal and suspicious ports
    ports = [80, 443, 22, 25, 53, 110, 993, 995,  # Normal
             4444, 5555, 31337, 12345, 1337]      # Suspicious
    
    print(f"Generating {count} TCP packets...")
    
    for i in range(count):
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        dst_port = random.choice(ports)
        
        # Create TCP packet
        tcp_packet = IP(src=src_ip, dst=dst_ip) / \
                    TCP(sport=random.randint(32768, 65535), 
                        dport=dst_port,
                        flags="S")  # SYN packet
        
        packets.append(tcp_packet)
        
        # Add some large packets for data exfiltration simulation
        if random.random() > 0.8:  # 20% chance
            large_data = "A" * random.randint(1400, 2000)  # Large payload
            large_packet = IP(src=src_ip, dst=dst_ip) / \
                          TCP(sport=random.randint(32768, 65535), 
                              dport=dst_port) / \
                          Raw(load=large_data)
            packets.append(large_packet)


def generate_icmp_traffic(packets, count=10):
    """Generate ICMP traffic"""
    src_ips = ["192.168.1.10", "192.168.1.15"]
    dst_ips = ["8.8.8.8", "1.1.1.1", "203.0.113.10"]
    
    print(f"Generating {count} ICMP packets...")
    
    for i in range(count):
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        
        # Create ICMP ping
        icmp_packet = IP(src=src_ip, dst=dst_ip) / ICMP()
        packets.append(icmp_packet)


def main():
    """Generate sample PCAP file"""
    print("🔧 Generating sample network traffic data...")
    
    packets = []
    
    # Generate different types of traffic
    generate_dns_traffic(packets, 50)
    generate_http_traffic(packets, 30)
    generate_tcp_traffic(packets, 40)
    generate_icmp_traffic(packets, 10)
    
    # Shuffle packets to make it more realistic
    random.shuffle(packets)
    
    # Add timestamps
    base_time = time.time() - 3600  # 1 hour ago
    for i, packet in enumerate(packets):
        packet.time = base_time + (i * random.uniform(0.1, 10.0))
    
    # Sort by timestamp
    packets.sort(key=lambda x: x.time)
    
    # Save to file
    output_file = "captures/sample.pcap"
    print(f"💾 Saving {len(packets)} packets to {output_file}")
    
    wrpcap(output_file, packets)
    
    print(f"✅ Sample PCAP file generated successfully!")
    print(f"📊 File size: {os.path.getsize(output_file)} bytes")
    print(f"📦 Total packets: {len(packets)}")
    print("\n🚀 You can now test the analyzer with:")
    print(f"   python analyzer.py --pcap {output_file}")
    print(f"   python web_app.py")


if __name__ == "__main__":
    main()