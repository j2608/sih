#!/usr/bin/env python3
"""
VNC Security Monitor - No-Install Demo Runner
Runs the demo without any package installation
"""

import os
import sys

def check_flask():
    """Check if Flask is available"""
    try:
        import flask
        return True
    except ImportError:
        return False

def run_basic_demo():
    """Run demo with built-in Python only"""
    print("🚀 VNC Security Monitor - Basic Demo")
    print("=" * 50)
    print("⚠️  Running in basic mode (no Flask)")
    print("📊 Simulating VNC threat detection...")
    
    # Simulate threat detection without web interface
    import random
    import time
    from datetime import datetime
    
    threats = [
        "📁 Large File Transfer (50MB) - HIGH RISK",
        "📋 Clipboard Data Exfiltration (25KB) - MEDIUM RISK", 
        "🗄️ Database Dump Detected - HIGH RISK",
        "🔐 Encoded Data Transfer - MEDIUM RISK",
        "🖼️ Screenshot Exfiltration - MEDIUM RISK"
    ]
    
    print("\n🔍 Starting VNC Traffic Analysis...")
    print("-" * 40)
    
    for i in range(10):
        time.sleep(1)
        if random.random() < 0.3:  # 30% chance of threat
            threat = random.choice(threats)
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"🚨 [{timestamp}] ALERT: {threat}")
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"✅ [{timestamp}] Normal VNC traffic")
    
    print("\n📊 Demo Summary:")
    print("✅ VNC traffic monitoring: ACTIVE")
    print("✅ Threat detection: FUNCTIONAL") 
    print("✅ ML anomaly detection: SIMULATED")
    print("✅ Attack scenarios: DEMONSTRATED")
    
    print("\n💡 For full web dashboard:")
    print("   1. Install Flask: pip install Flask")
    print("   2. Run: python simple_app.py")

def main():
    """Main demo runner"""
    print("🎯 VNC Security Monitor - Demo Launcher")
    print("=" * 50)
    
    if check_flask():
        print("✅ Flask detected - Starting web dashboard...")
        try:
            # Import and run the simple app
            from simple_app import app
            print("🌐 Dashboard starting at: http://localhost:5000")
            print("🎭 Click attack simulation buttons to see detection!")
            app.run(debug=False, host='0.0.0.0', port=5000)
        except Exception as e:
            print(f"❌ Web app failed: {e}")
            print("🔄 Falling back to basic demo...")
            run_basic_demo()
    else:
        print("⚠️  Flask not found - Running basic demo...")
        run_basic_demo()

if __name__ == "__main__":
    main()