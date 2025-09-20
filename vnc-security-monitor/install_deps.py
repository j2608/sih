#!/usr/bin/env python3
"""
Simple dependency installer that handles Python 3.13 issues
"""

import subprocess
import sys
import os

def fix_setuptools_first():
    """Fix setuptools issue common in Python 3.13"""
    print("🔧 Fixing setuptools for Python 3.13...")
    try:
        # Try to upgrade pip and setuptools first
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "setuptools"], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ Setuptools fixed!")
        return True
    except:
        print("⚠️  Setuptools fix failed, trying alternative approach...")
        return False

def install_minimal_deps():
    """Install only essential packages"""
    print("📦 Installing minimal dependencies...")
    
    # Try Flask first (most important)
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "Flask"], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ Flask installed!")
    except:
        print("❌ Flask installation failed")
        return False
    
    # Try other packages one by one
    optional_packages = ["pandas", "numpy", "scikit-learn", "joblib", "faker"]
    installed = []
    
    for package in optional_packages:
        try:
            print(f"   Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            installed.append(package)
            print(f"✅ {package} installed!")
        except:
            print(f"⚠️  {package} failed, skipping...")
    
    print(f"\n📊 Installed packages: {', '.join(['Flask'] + installed)}")
    return True

def create_basic_setup():
    """Create basic directory structure"""
    print("📁 Creating directories...")
    directories = ['data', 'models', 'logs', 'templates']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"   Created: {directory}")

def main():
    print("🚀 VNC Security Monitor - Simple Installer")
    print("=" * 50)
    
    # Fix setuptools issue
    fix_setuptools_first()
    
    # Create directories
    create_basic_setup()
    
    # Install dependencies
    if install_minimal_deps():
        print("\n🎉 Installation Complete!")
        print("=" * 50)
        print("✅ Ready to run the demo!")
        print("\nNext steps:")
        print("1. python simple_app.py    (Guaranteed to work)")
        print("2. python quickstart.py    (Alternative)")
        print("3. Open: http://localhost:5000")
    else:
        print("\n❌ Installation Failed")
        print("=" * 50)
        print("💡 Try manual installation:")
        print("   pip install --upgrade pip setuptools")
        print("   pip install Flask")
        print("   python simple_app.py")

if __name__ == "__main__":
    main()