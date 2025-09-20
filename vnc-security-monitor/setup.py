#!/usr/bin/env python3
"""
VNC Security Monitor - Quick Setup Script
Sets up the environment and runs initial training
"""

import subprocess
import sys
import os

def install_requirements():
    """Install required packages"""
    print("📦 Installing required packages...")
    try:
        # Install packages one by one to better handle errors
        packages = [
            "Flask==2.3.3",
            "pandas==2.0.3", 
            "numpy==1.24.3",
            "scikit-learn==1.3.0",
            "joblib==1.3.2",
            "faker==19.6.2"
        ]
        
        for package in packages:
            print(f"   Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print("✅ Packages installed successfully!")
        return True
    except Exception as e:
        print(f"❌ Package installation failed: {e}")
        print("💡 Try running: pip install -r requirements.txt manually")
        return False

def setup_directories():
    """Create necessary directories"""
    directories = ['data', 'models', 'logs']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"📁 Created directory: {directory}")

def run_initial_setup():
    """Run initial data generation and model training"""
    print("🔄 Running initial setup...")
    
    try:
        # Import after packages are installed
        sys.path.insert(0, os.getcwd())
        
        print("📊 Generating synthetic training data...")
        # Create minimal data generation inline to avoid import issues
        import pandas as pd
        import numpy as np
        from datetime import datetime, timedelta
        import random
        
        # Simple data generation
        np.random.seed(42)
        random.seed(42)
        
        sessions = []
        for i in range(100):  # Smaller dataset for quick setup
            is_anomaly = i < 15  # 15% anomalies
            
            session = {
                'session_id': f'sess-{i:03d}',
                'user_id': f'user_{i%10}',
                'duration_seconds': np.random.normal(1800, 600) if not is_anomaly else np.random.normal(3600, 1200),
                'total_bytes_out': np.random.lognormal(13, 1) if not is_anomaly else np.random.lognormal(16, 1),
                'num_clipboard_events': np.random.poisson(0.5) if not is_anomaly else np.random.poisson(10),
                'total_clipboard_bytes': np.random.exponential(2048) if not is_anomaly else np.random.exponential(100000),
                'num_screenshot_events': np.random.poisson(1) if not is_anomaly else np.random.poisson(20),
                'avg_frame_rate': np.random.uniform(3, 8) if not is_anomaly else np.random.uniform(15, 30),
                'device_trust_score': np.random.beta(8, 2) if not is_anomaly else np.random.beta(2, 8),
                'label': 'anomalous' if is_anomaly else 'normal'
            }
            sessions.append(session)
        
        sessions_df = pd.DataFrame(sessions)
        
        # Save data
        os.makedirs('data', exist_ok=True)
        sessions_df.to_csv('data/session_logs.csv', index=False)
        print(f"✅ Generated {len(sessions_df)} training sessions")
        
        # Simple model training
        print("🤖 Training basic ML model...")
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import joblib
        
        # Select numeric features
        feature_cols = ['duration_seconds', 'total_bytes_out', 'num_clipboard_events', 
                       'total_clipboard_bytes', 'num_screenshot_events', 'avg_frame_rate', 
                       'device_trust_score']
        
        X = sessions_df[feature_cols].fillna(0)
        
        # Scale and train
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        model = IsolationForest(contamination=0.15, random_state=42)
        model.fit(X_scaled)
        
        # Save model
        os.makedirs('models', exist_ok=True)
        joblib.dump({
            'model': model,
            'scaler': scaler,
            'feature_columns': feature_cols
        }, 'models/simple_vnc_model.joblib')
        
        print("✅ Basic model trained and saved!")
        return True
        
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        print("💡 You can still run the app, it will work with rule-based detection")
        return False

def main():
    """Main setup function"""
    print("🚀 VNC Security Monitor - Quick Setup")
    print("=" * 50)
    
    setup_directories()
    
    # Try to install packages
    packages_ok = install_requirements()
    
    if packages_ok:
        # Try to run initial setup
        setup_ok = run_initial_setup()
    else:
        print("⚠️  Skipping ML setup due to package installation issues")
        setup_ok = False
    
    print("\n" + "=" * 50)
    if packages_ok and setup_ok:
        print("🎉 Complete Setup Successful!")
        print("✅ All components ready")
    elif packages_ok:
        print("⚠️  Partial Setup Complete")
        print("✅ Packages installed, basic functionality available")
    else:
        print("⚠️  Minimal Setup Complete")
        print("💡 Manual package installation may be needed")
    
    print("\n📋 Next Steps:")
    print("1. Start the application: python app.py")
    print("2. Open browser: http://localhost:5000")
    print("3. Try attack simulations in the dashboard")
    
    if not setup_ok:
        print("\n💡 For full ML features, ensure all packages are installed:")
        print("   pip install pandas numpy scikit-learn joblib faker flask")

if __name__ == "__main__":
    main()