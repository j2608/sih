#!/usr/bin/env python3
"""
VNC Security Monitor - Quick Start for Hackathon Demo
Minimal setup that works immediately
"""

import os
import sys

def check_dependencies():
    """Check if required packages are available"""
    required = ['flask']
    missing = []
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    return missing

def install_flask():
    """Install Flask if missing"""
    try:
        import subprocess
        print("📦 Installing Flask...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "flask"], 
                            stdout=subprocess.DEVNULL)
        print("✅ Flask installed!")
        return True
    except:
        print("❌ Failed to install Flask")
        return False

def main():
    """Quick start the demo"""
    print("🚀 VNC Security Monitor - Quick Start")
    print("=" * 50)
    
    # Check dependencies
    missing = check_dependencies()
    
    if 'flask' in missing:
        print("⚠️  Flask not found, attempting to install...")
        if not install_flask():
            print("❌ Cannot install Flask. Please run: pip install flask")
            return
    
    # Create directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('data', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    print("✅ Setup complete!")
    print("\n🎯 Starting VNC Security Monitor Demo...")
    print("📊 Dashboard will open at: http://localhost:5000")
    print("\n💡 Demo Features:")
    print("   • Real-time threat detection simulation")
    print("   • Attack scenario demonstrations")
    print("   • ML-powered anomaly detection")
    print("   • Interactive security dashboard")
    
    # Start the simple app
    try:
        from simple_app import app, detector
        print("\n🔥 Starting demo server...")
        app.run(debug=False, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        print("\n💡 Try running manually:")
        print("   python simple_app.py")

if __name__ == "__main__":
    main()