# 🔒 NetTrafficAnalyzer

**Advanced Network Traffic Analysis & Security Monitoring Tool**

A comprehensive Python-based toolset for analyzing network traffic, detecting anomalies, and securing network protocols with a modern web interface for real-time analysis and visualization.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

## ✨ Features

### 🔍 Advanced Analysis Capabilities
- **Multi-Protocol Support**: Parse TCP/IP, DNS, HTTP, UDP, and ICMP packets from PCAP files
- **Intelligent Anomaly Detection**: Detect suspicious patterns including:
  - Unusual port activity and connections to suspicious ports
  - DNS anomalies (DGA domains, suspicious TTL values)
  - HTTP security threats (SQL injection, XSS, suspicious user agents)
  - Data exfiltration patterns (high-volume conversations)
  - Large packet detection and protocol anomalies
- **Comprehensive Reporting**: Export detailed analysis in CSV and JSON formats
- **Real-time Analysis**: Process live network captures with instant feedback

### 🌐 Modern Web Interface
- **Interactive Dashboard**: Beautiful, responsive web interface built with Dash and Bootstrap
- **Real-time Visualizations**: Interactive charts and graphs using Plotly
- **Multi-tab Analysis Views**:
  - 📊 **Overview**: Protocol distribution and port activity
  - 🚨 **Anomalies**: Detailed threat detection and alerts
  - 📡 **Protocols**: Network protocol analysis and statistics
  - 🌐 **Network Analysis**: IP conversations and traffic patterns
  - 📈 **Timeline Analysis**: Traffic patterns over time
- **File Upload Interface**: Drag-and-drop PCAP file upload
- **Report Downloads**: Export analysis results directly from the web interface

### 🛡️ Security Features
- **Threat Detection**: Automatically identify potential security threats
- **Attack Pattern Recognition**: Detect common attack vectors and tools
- **Network Forensics**: Comprehensive traffic analysis for incident response
- **Compliance Reporting**: Generate reports suitable for security audits

## 🛠️ Tech Stack

- **Backend**: Python 3.8+, Flask, Scapy, PyShark
- **Frontend**: Dash, Plotly, Bootstrap, HTML5/CSS3
- **Data Processing**: Pandas, NumPy
- **Visualization**: Plotly Express, Plotly Graph Objects
- **Network Analysis**: Scapy for packet manipulation and analysis

## 📦 Installation

### Quick Start
```bash
# Clone the repository
git clone https://github.com/ravitejaannam-008/NetTrafficAnalyzer.git
cd NetTrafficAnalyzer

# Install dependencies
pip install -r requirements.txt

# Run the application (auto-installs dependencies and generates sample data)
python run.py
```

### Manual Installation
```bash
# Install individual dependencies
pip install scapy==2.5.0
pip install pyshark==0.6
pip install pandas==2.0.3
pip install flask==2.3.3
pip install dash==2.14.1
pip install plotly==5.17.0
pip install dash-bootstrap-components==1.5.0

# For Wireshark support (optional)
# Ubuntu/Debian: apt-get install wireshark
# macOS: brew install wireshark
# Windows: Download from https://www.wireshark.org/
```

## 🚀 Usage

### Web Interface (Recommended)
```bash
# Start the web application
python run.py

# Or directly run the web app
python web_app.py
```
Access the dashboard at: **http://localhost:8050**

### Command Line Interface
```bash
# Analyze a PCAP file
python analyzer.py --pcap captures/sample.pcap --output reports/analysis.csv

# Verbose analysis with JSON output
python analyzer.py --pcap captures/sample.pcap --json-output reports/analysis.json --verbose

# Generate sample data for testing
python generate_sample.py
```

### API Usage
The tool also provides a REST API for programmatic access:

```bash
# Analyze via API
curl -X POST -F "file=@captures/sample.pcap" http://localhost:8050/api/analyze

# Download reports
curl http://localhost:8050/api/download_report/csv -o report.csv
curl http://localhost:8050/api/download_report/json -o report.json
```

## 📋 Example Analysis

```bash
$ python analyzer.py --pcap captures/sample.pcap --verbose

Loading PCAP file: captures/sample.pcap
Successfully loaded 157 packets
Starting comprehensive network traffic analysis...
Analysis complete! Found 8 anomalies

==================================================
NETWORK TRAFFIC ANALYSIS SUMMARY
==================================================
Total Packets: 157
DNS Queries: 50
HTTP Requests: 30
Anomalies Detected: 8
Average Packet Size: 247.83 bytes

DETECTED ANOMALIES:
1. Suspicious DNS Query: Unusually long domain name: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.malicious...
2. Suspicious User Agent: Potential security tool detected: sqlmap/1.4.2
3. Potential SQL Injection: Suspicious pattern in URL: 1=1
4. Unusual Port Activity: Connection to suspicious port 4444
5. Large Packet: Unusually large packet: 1847 bytes

Analysis completed successfully!
CSV report exported to: reports/traffic_analysis_report.csv
```

## 📊 Dashboard Features

### Upload & Analysis
- **Drag & Drop**: Easy PCAP file upload interface
- **Real-time Processing**: Live analysis progress with instant results
- **Format Validation**: Automatic PCAP file format verification

### Interactive Visualizations
- **Protocol Distribution**: Pie charts showing traffic breakdown
- **Port Activity**: Bar charts of most active ports
- **Anomaly Analysis**: Categorized threat detection with severity levels
- **Timeline Graphs**: Traffic patterns and packet size distributions
- **Network Maps**: IP conversation analysis and traffic flows

### Export Capabilities
- **Multiple Formats**: CSV and JSON report generation
- **Downloadable Reports**: Direct download from web interface
- **Detailed Analysis**: Comprehensive anomaly descriptions and timestamps

## 🛡️ Security Detection Capabilities

### Network Anomalies
- **Port Scanning**: Detection of unusual port access patterns
- **Protocol Anomalies**: Identification of unexpected protocol usage
- **Traffic Volume**: Large data transfer detection

### DNS Security
- **DGA Detection**: Domain Generation Algorithm identification
- **DNS Tunneling**: Suspicious DNS query patterns
- **TTL Anomalies**: Unusual Time-To-Live values

### HTTP Security
- **SQL Injection**: Detection of common SQLi patterns
- **XSS Attempts**: Cross-site scripting pattern recognition
- **Tool Detection**: Identification of security testing tools
- **Suspicious User Agents**: Automated tool and bot detection

### Data Exfiltration
- **Volume Analysis**: High-volume data transfer detection
- **Pattern Recognition**: Unusual conversation patterns
- **Protocol Abuse**: Detection of protocol misuse for data theft

## 📁 Project Structure

```
NetTrafficAnalyzer/
├── analyzer.py              # Core analysis engine
├── web_app.py              # Web interface application
├── run.py                  # Startup script
├── generate_sample.py      # Sample data generator
├── requirements.txt        # Python dependencies
├── README.md              # Project documentation
├── captures/              # PCAP files directory
│   └── sample.pcap        # Generated sample data
├── reports/               # Analysis reports
├── uploads/               # Web interface uploads
└── .git/                  # Git repository
```

## 🔧 Configuration

### Anomaly Detection Thresholds
The analyzer uses configurable thresholds for anomaly detection:

```python
thresholds = {
    'unusual_ports': [22, 23, 3389, 4444, 5555],  # Suspicious ports
    'max_dns_ttl': 86400,                         # 24 hours
    'min_dns_ttl': 60,                            # 1 minute
    'large_packet_threshold': 1500,               # MTU size
    'suspicious_user_agents': ['sqlmap', 'nmap'], # Security tools
    'max_connections_per_ip': 100                 # Connection limit
}
```

### Web Interface Settings
```python
# Server configuration
HOST = '0.0.0.0'          # Listen on all interfaces
PORT = 8050               # Web server port
MAX_FILE_SIZE = 100MB     # Maximum PCAP file size
DEBUG = False             # Production mode
```

## 🚨 Security Considerations

- **File Upload Security**: Automatic filename sanitization and validation
- **Resource Limits**: Maximum file size and processing time limits
- **Input Validation**: Comprehensive input sanitization for all user data
- **Error Handling**: Graceful error handling to prevent information disclosure

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** and add tests
4. **Run tests**: `python -m pytest tests/`
5. **Submit a pull request**

### Development Setup
```bash
# Clone for development
git clone https://github.com/ravitejaannam-008/NetTrafficAnalyzer.git
cd NetTrafficAnalyzer

# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8

# Run tests
python -m pytest

# Format code
black . --line-length 88
```

## 📈 Future Enhancements

- [ ] **Machine Learning Integration**: AI-powered anomaly detection
- [ ] **Real-time Monitoring**: Live network interface capture
- [ ] **Advanced Visualizations**: Network topology mapping
- [ ] **Alert System**: Email/SMS notifications for critical threats
- [ ] **Database Integration**: Historical analysis and trend tracking
- [ ] **Plugin System**: Extensible analysis modules
- [ ] **Multi-user Support**: User authentication and role management

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Raviteja Annam**
- Network Security Engineer at Indian Railways
- 3+ years experience in network forensics and traffic analysis
- Expert in Wireshark, Python network programming, and security automation
- Passionate about developing tools that solve real-world cybersecurity challenges

## 🙏 Acknowledgments

- **Wireshark Project**: For excellent packet analysis capabilities
- **Scapy Community**: For powerful Python packet manipulation
- **Dash/Plotly**: For beautiful web visualizations
- **Flask**: For robust web framework foundation

## 📞 Support

- **Issues**: Report bugs and feature requests on [GitHub Issues](https://github.com/ravitejaannam-008/NetTrafficAnalyzer/issues)
- **Discussions**: Join conversations in [GitHub Discussions](https://github.com/ravitejaannam-008/NetTrafficAnalyzer/discussions)
- **Email**: Contact for enterprise support and consulting

---

**Built with ❤️ for network security professionals and researchers**

## 💡 Project Background

During my tenure as a Network Security Engineer at Indian Railways, I frequently used Wireshark for manual traffic analysis to detect data exfiltration and security threats. This repetitive process highlighted the need for an automated, comprehensive solution. I developed NetTrafficAnalyzer to:

- **Automate Detection**: Replace manual analysis with intelligent anomaly detection
- **Improve Efficiency**: Process large PCAP files quickly with detailed reporting  
- **Enhance Visualization**: Provide intuitive dashboards for security teams
- **Scale Analysis**: Handle enterprise-level network monitoring requirements

This project demonstrates my ability to identify real-world problems and develop practical, enterprise-ready solutions using modern technologies.
