#!/usr/bin/env python3
"""
NetTrafficAnalyzer Startup Script
Simplified launcher for the network traffic analyzer
"""

import os
import sys
import subprocess


def check_dependencies():
    """Check if required packages are installed"""
    required_packages = ['scapy', 'flask', 'dash', 'pandas', 'plotly']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    return missing_packages


def install_dependencies():
    """Install missing dependencies"""
    print("📦 Installing required dependencies...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return False


def generate_sample_data():
    """Generate sample PCAP data if not exists"""
    if not os.path.exists('captures/sample.pcap'):
        print("🔧 Generating sample PCAP data...")
        try:
            subprocess.check_call([sys.executable, 'generate_sample.py'])
        except subprocess.CalledProcessError:
            print("⚠️ Failed to generate sample data, continuing without it...")


def main():
    """Main startup function"""
    print("🚀 NetTrafficAnalyzer Startup")
    print("=" * 40)
    
    # Check dependencies
    missing = check_dependencies()
    if missing:
        print(f"⚠️ Missing packages: {', '.join(missing)}")
        if not install_dependencies():
            print("Please install manually: pip install -r requirements.txt")
            return 1
    
    # Generate sample data
    generate_sample_data()
    
    # Start web application
    print("\n🌐 Starting web application...")
    print("📊 Dashboard will be available at: http://localhost:8050")
    print("🛑 Press Ctrl+C to stop\n")
    
    try:
        # Import and run the web app
        from web_app import app
        app.run_server(debug=False, host='0.0.0.0', port=8050)
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please ensure all dependencies are installed")
        return 1
    except KeyboardInterrupt:
        print("\n👋 Shutting down gracefully...")
        return 0


if __name__ == "__main__":
    exit(main())