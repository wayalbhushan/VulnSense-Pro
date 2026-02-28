# VulnSense Pro 🛡️
**Enterprise-Grade Network Auditor & IDS with Real-time Entropy Analysis.**

VulnSense Pro is a security tool designed for real-time network auditing, credential leak detection, and DNS exfiltration monitoring. It features a professional Terminal User Interface (TUI) and uses mathematical entropy analysis to detect stealthy data exfiltration.

## 🚀 Key Features
- **Asynchronous UI:** Multi-threaded architecture allowing for live sniffing and manual state saving (**Ctrl+S**).
- **Shannon Entropy Engine:** Detects 0-day DNS tunnels by analyzing subdomain randomness.
- **Sensitive Data Sniffer:** Regex-based detection for JWT, AWS Keys, and HTTP credentials.
- **Enterprise TUI:** Professional dashboard built with the `rich` library.
## Dashboard View 
 ![Dashboard(./Dashboard.png)##
```bash
# Run the master deployer
sudo ./scripts/vulnsense.sh
```

## 🧠 Technical Highlights
- **Engine:** Python 3.9+ / Scapy
- **UI:** Threaded Rendering with Rich Layouts
- **Math:** Shannon Entropy for 0-day tunnel detection.
