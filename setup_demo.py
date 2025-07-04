#!/usr/bin/env python3
"""
NetTrafficAnalyzer Setup & Demo
Complete demonstration of the enhanced network traffic analyzer
"""

import os
import sys
import subprocess
import time
import webbrowser
from pathlib import Path


def print_banner():
    """Print welcome banner"""
    banner = """
🔒 ════════════════════════════════════════════════════════════════════════════════ 🔒
   
    ███╗   ██╗███████╗████████╗████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗
    ████╗  ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝
    ██╔██╗ ██║█████╗     ██║      ██║   ██████╔╝███████║█████╗  █████╗  ██║██║     
    ██║╚██╗██║██╔══╝     ██║      ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║     
    ██║ ╚████║███████╗   ██║      ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝
                                                                                    
          🛡️  Advanced Network Traffic Analysis & Security Monitoring Tool  🛡️
                     
🔒 ════════════════════════════════════════════════════════════════════════════════ 🔒
"""
    print(banner)


def check_system():
    """Check system requirements"""
    print("🔍 System Check")
    print("-" * 40)
    
    # Check Python version
    python_version = sys.version_info
    if python_version >= (3, 8):
        print(f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro}")
    else:
        print(f"❌ Python {python_version.major}.{python_version.minor} (3.8+ required)")
        return False
    
    # Check pip
    try:
        subprocess.check_output([sys.executable, '-m', 'pip', '--version'])
        print("✅ pip available")
    except subprocess.CalledProcessError:
        print("❌ pip not available")
        return False
    
    # Check git
    try:
        subprocess.check_output(['git', '--version'])
        print("✅ git available")
    except subprocess.CalledProcessError:
        print("⚠️ git not available (optional)")
    
    return True


def setup_environment():
    """Set up the development environment"""
    print("\n📦 Environment Setup")
    print("-" * 40)
    
    # Install dependencies
    print("Installing Python dependencies...")
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ Dependencies installed")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return False
    
    # Create directories
    directories = ['captures', 'reports', 'uploads']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    print(f"✅ Created directories: {', '.join(directories)}")
    
    return True


def generate_demo_data():
    """Generate sample PCAP data"""
    print("\n🔧 Demo Data Generation")
    print("-" * 40)
    
    if not os.path.exists('captures/sample.pcap'):
        print("Generating sample network traffic data...")
        try:
            subprocess.check_call([sys.executable, 'generate_sample.py'])
            print("✅ Sample PCAP data generated")
        except subprocess.CalledProcessError:
            print("❌ Failed to generate sample data")
            return False
    else:
        print("✅ Sample PCAP data already exists")
    
    return True


def demo_cli_analysis():
    """Demonstrate CLI analysis"""
    print("\n💻 CLI Analysis Demo")
    print("-" * 40)
    
    print("Running command-line analysis...")
    try:
        result = subprocess.run([
            sys.executable, 'analyzer.py', 
            '--pcap', 'captures/sample.pcap',
            '--output', 'reports/demo_analysis.csv',
            '--json-output', 'reports/demo_analysis.json',
            '--verbose'
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ CLI analysis completed successfully")
            print("\n📄 Generated reports:")
            print("   📊 CSV: reports/demo_analysis.csv")
            print("   📋 JSON: reports/demo_analysis.json")
            
            # Show sample output
            lines = result.stdout.split('\n')
            summary_started = False
            for line in lines[-15:]:  # Last 15 lines
                if 'SUMMARY' in line or summary_started:
                    summary_started = True
                    if line.strip():
                        print(f"   {line}")
        else:
            print(f"❌ CLI analysis failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ CLI analysis timed out")
        return False
    except Exception as e:
        print(f"❌ CLI analysis error: {e}")
        return False
    
    return True


def start_web_interface():
    """Start the web interface"""
    print("\n🌐 Web Interface Launch")
    print("-" * 40)
    
    print("Starting web application...")
    print("📊 Dashboard URL: http://localhost:8050")
    print("🚀 Opening browser in 3 seconds...")
    
    # Start web app in background
    try:
        # Open browser after a short delay
        time.sleep(3)
        webbrowser.open('http://localhost:8050')
        
        print("\n🎯 Web Interface Features:")
        print("   📁 Drag & drop PCAP file upload")
        print("   📊 Interactive visualizations")
        print("   🚨 Real-time anomaly detection")
        print("   📈 Multiple analysis views")
        print("   💾 Report downloads")
        
        print("\n🛑 Press Ctrl+C to stop the server")
        
        # Run the web app
        subprocess.check_call([sys.executable, 'run.py'])
        
    except KeyboardInterrupt:
        print("\n👋 Web interface stopped")
    except Exception as e:
        print(f"❌ Web interface error: {e}")


def show_project_structure():
    """Display project structure"""
    print("\n📁 Project Structure")
    print("-" * 40)
    
    structure = """
NetTrafficAnalyzer/
├── 🔍 analyzer.py              # Core analysis engine
├── 🌐 web_app.py               # Web interface
├── 🚀 run.py                   # Startup script  
├── 🎭 demo_api.py              # API demonstration
├── 🔧 generate_sample.py       # Sample data generator
├── 📋 setup_demo.py            # This setup script
├── 📖 README.md                # Documentation
├── 📄 LICENSE                  # MIT License
├── 📦 requirements.txt         # Dependencies
├── 📂 captures/                # PCAP files
│   └── 📊 sample.pcap         # Generated sample
├── 📂 reports/                 # Analysis reports
├── 📂 uploads/                 # Web uploads
└── 📂 .git/                   # Git repository
"""
    
    print(structure)


def show_usage_examples():
    """Show usage examples"""
    print("\n📚 Usage Examples")
    print("-" * 40)
    
    examples = """
🚀 Quick Start:
   python run.py                              # Start web interface
   
💻 Command Line:
   python analyzer.py --pcap file.pcap        # Basic analysis
   python analyzer.py --pcap file.pcap -v     # Verbose output
   python analyzer.py --help                  # Show all options
   
🎭 API Demo:
   python demo_api.py                         # Run API demonstrations
   
🔧 Generate Sample Data:
   python generate_sample.py                  # Create test PCAP file
   
🌐 Web API:
   curl -X POST -F "file=@file.pcap" \\
        http://localhost:8050/api/analyze     # Analyze via API
"""
    
    print(examples)


def main():
    """Main setup and demo function"""
    print_banner()
    
    # System check
    if not check_system():
        print("\n❌ System requirements not met")
        return 1
    
    # Environment setup
    if not setup_environment():
        print("\n❌ Environment setup failed")
        return 1
    
    # Generate demo data
    if not generate_demo_data():
        print("\n❌ Demo data generation failed")
        return 1
    
    # CLI demo
    if not demo_cli_analysis():
        print("\n❌ CLI demo failed")
        return 1
    
    # Show project info
    show_project_structure()
    show_usage_examples()
    
    # Ask user about web interface
    print("\n🌐 Web Interface")
    print("-" * 40)
    response = input("Start web interface? (y/n): ").lower().strip()
    
    if response in ['y', 'yes']:
        start_web_interface()
    else:
        print("\n✅ Setup completed successfully!")
        print("\n🚀 You can start the web interface anytime with:")
        print("   python run.py")
        print("\n📖 See README.md for complete documentation")
    
    return 0


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n\n👋 Setup interrupted by user")
        exit(0)
    except Exception as e:
        print(f"\n❌ Setup error: {e}")
        exit(1)