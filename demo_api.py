#!/usr/bin/env python3
"""
NetTrafficAnalyzer API Demo
Demonstrates programmatic usage of the network traffic analyzer
"""

import requests
import json
import time
import os


def demo_cli_analysis():
    """Demonstrate command-line analysis"""
    print("🔧 CLI Analysis Demo")
    print("-" * 30)
    
    # Use the analyzer directly
    from analyzer import NetworkTrafficAnalyzer
    
    analyzer = NetworkTrafficAnalyzer()
    
    # Check if sample data exists
    if not os.path.exists('captures/sample.pcap'):
        print("⚠️ Sample PCAP not found. Generating...")
        os.system('python generate_sample.py')
    
    # Load and analyze
    if analyzer.load_pcap('captures/sample.pcap'):
        results = analyzer.run_full_analysis()
        
        print(f"✅ Analysis Complete:")
        print(f"   📦 Total Packets: {results['summary']['total_packets']}")
        print(f"   🚨 Anomalies: {results['summary']['total_anomalies']}")
        print(f"   🌐 DNS Queries: {results['summary']['dns_queries']}")
        print(f"   📡 HTTP Requests: {results['summary']['http_requests']}")
        
        # Show some anomalies
        if results['detailed_results']['anomalies']:
            print(f"\n🔍 Sample Anomalies:")
            for i, anomaly in enumerate(results['detailed_results']['anomalies'][:3], 1):
                print(f"   {i}. {anomaly['type']}: {anomaly['description'][:50]}...")


def demo_web_api():
    """Demonstrate web API usage"""
    print("\n🌐 Web API Demo")
    print("-" * 30)
    
    base_url = "http://localhost:8050"
    
    # Check if server is running
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        print("✅ Web server is running")
    except requests.exceptions.RequestException:
        print("❌ Web server not running. Start with: python run.py")
        return
    
    # Test file upload API
    if os.path.exists('captures/sample.pcap'):
        try:
            with open('captures/sample.pcap', 'rb') as f:
                files = {'file': f}
                response = requests.post(f"{base_url}/api/analyze", files=files, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                print("✅ API Analysis Complete:")
                print(f"   📦 Total Packets: {data['summary']['total_packets']}")
                print(f"   🚨 Anomalies: {data['summary']['total_anomalies']}")
                
                # Test report download
                csv_response = requests.get(f"{base_url}/api/download_report/csv", timeout=10)
                if csv_response.status_code == 200:
                    print("✅ CSV report download successful")
                
                json_response = requests.get(f"{base_url}/api/download_report/json", timeout=10)
                if json_response.status_code == 200:
                    print("✅ JSON report download successful")
                    
            else:
                print(f"❌ API error: {response.status_code}")
                
        except Exception as e:
            print(f"❌ API request failed: {e}")
    else:
        print("❌ Sample PCAP file not found")


def demo_custom_analysis():
    """Demonstrate custom analysis configurations"""
    print("\n⚙️ Custom Analysis Demo")
    print("-" * 30)
    
    from analyzer import NetworkTrafficAnalyzer
    
    # Create analyzer with custom thresholds
    analyzer = NetworkTrafficAnalyzer()
    
    # Modify detection thresholds
    analyzer.thresholds.update({
        'large_packet_threshold': 1000,  # Lower threshold
        'unusual_ports': [21, 22, 23, 25, 53, 80, 443, 993, 995, 4444, 5555],
        'suspicious_user_agents': ['curl', 'wget', 'sqlmap', 'nmap', 'nikto']
    })
    
    print("🔧 Modified Detection Thresholds:")
    print(f"   📏 Large packet threshold: {analyzer.thresholds['large_packet_threshold']} bytes")
    print(f"   🚪 Monitoring {len(analyzer.thresholds['unusual_ports'])} suspicious ports")
    print(f"   🤖 Detecting {len(analyzer.thresholds['suspicious_user_agents'])} suspicious user agents")
    
    # Run analysis with custom settings
    if os.path.exists('captures/sample.pcap') and analyzer.load_pcap('captures/sample.pcap'):
        results = analyzer.run_full_analysis()
        print(f"✅ Custom analysis found {results['summary']['total_anomalies']} anomalies")


def demo_batch_processing():
    """Demonstrate batch processing of multiple files"""
    print("\n📁 Batch Processing Demo")
    print("-" * 30)
    
    # Create sample files for demo
    pcap_files = []
    if os.path.exists('captures/sample.pcap'):
        pcap_files.append('captures/sample.pcap')
    
    if not pcap_files:
        print("⚠️ No PCAP files found for batch processing")
        return
    
    results_summary = []
    
    for pcap_file in pcap_files:
        print(f"🔍 Analyzing {pcap_file}...")
        
        from analyzer import NetworkTrafficAnalyzer
        analyzer = NetworkTrafficAnalyzer()
        
        if analyzer.load_pcap(pcap_file):
            results = analyzer.run_full_analysis()
            summary = {
                'file': pcap_file,
                'packets': results['summary']['total_packets'],
                'anomalies': results['summary']['total_anomalies'],
                'timestamp': results['summary']['analysis_timestamp']
            }
            results_summary.append(summary)
            
            # Export individual reports
            base_name = os.path.splitext(os.path.basename(pcap_file))[0]
            csv_output = f"reports/batch_{base_name}.csv"
            analyzer.export_csv_report(csv_output)
    
    # Print batch summary
    print("\n📊 Batch Processing Summary:")
    for result in results_summary:
        print(f"   📄 {result['file']}: {result['packets']} packets, {result['anomalies']} anomalies")


def main():
    """Main demo function"""
    print("🚀 NetTrafficAnalyzer Demo")
    print("=" * 50)
    
    # Run different demo scenarios
    demo_cli_analysis()
    demo_web_api()
    demo_custom_analysis()
    demo_batch_processing()
    
    print("\n" + "=" * 50)
    print("✅ Demo completed!")
    print("\n📚 Learn more:")
    print("   🌐 Web Interface: http://localhost:8050")
    print("   📖 Documentation: README.md")
    print("   💻 CLI Help: python analyzer.py --help")


if __name__ == "__main__":
    main()