# 🚀 VNC Security Monitor - Quick Start Guide

## ⚡ Instant Demo (No Installation Required)

```bash
python run_demo.py
```
- ✅ Works with any Python installation
- ✅ No dependencies required
- ✅ Shows threat detection simulation
- ✅ Automatic fallback if Flask missing

## 🔧 Fix Python 3.13 Issues & Install

```bash
python install_deps.py
```
- ✅ Fixes setuptools issues
- ✅ Installs Flask and optional packages
- ✅ Creates necessary directories
- ✅ Handles installation failures gracefully

## 🌐 Web Dashboard Options

### Option 1: Simple Dashboard (Recommended)
```bash
python simple_app.py
```
- ✅ Minimal dependencies (Flask only)
- ✅ Full interactive dashboard
- ✅ Attack animations
- ✅ Real-time threat detection

### Option 2: Full ML Dashboard
```bash
python app.py
```
- ✅ Complete ML features
- ✅ Advanced analytics
- ✅ Requires all packages installed

### Option 3: Quick Start
```bash
python quickstart.py
```
- ✅ Auto-installs Flask if missing
- ✅ Immediate demo

## 🆘 If Everything Fails

### Manual Flask Installation:
```bash
pip install --upgrade pip setuptools
pip install Flask
python simple_app.py
```

### No-Install Demo:
```bash
python run_demo.py
```
- Shows command-line threat simulation
- Demonstrates core detection logic
- No web interface needed

## 🎯 For Hackathon Judges

**Fastest Demo Start:**
1. `python run_demo.py` - Instant demo
2. If web dashboard opens: Click attack buttons
3. If command-line demo: Watch threat detection

**Best Experience:**
1. `python install_deps.py` - Fix dependencies
2. `python simple_app.py` - Full dashboard
3. Open: http://localhost:5000
4. Click attack simulation buttons

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| setuptools error | `python install_deps.py` |
| Flask not found | `pip install Flask` |
| All packages fail | `python run_demo.py` |
| Port 5000 busy | Change port in simple_app.py |
| Permission errors | Run as administrator |

## 📊 What You'll See

- **Real-time threat monitoring**
- **Attack simulation buttons**
- **ML feature importance**
- **Animated attack visualizations**
- **Threat scenario matrix**
- **Automated remediation demos**

---
**Built for Smart India Hackathon 2025**  
*VNC Data Exfiltration Detection & Protection*