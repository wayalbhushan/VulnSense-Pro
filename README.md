# VulnSense Pro v3.5 🛡️
**Enterprise-Grade Network Auditor & IDS with Real-time Entropy Analysis.**

VulnSense Pro is a security tool designed for real-time network auditing, credential leak detection, and DNS exfiltration monitoring. It features a professional Terminal User Interface (TUI) and uses mathematical entropy analysis to detect stealthy data exfiltration.

## 🚀 Key Features
* **DNS Exfiltration Detection:** Uses Shannon Entropy to identify high-randomness subdomains.
* **Credential Sniffer:** Monitors for plaintext JWTs, AWS Keys, and HTTP credentials.
* **TUI Dashboard:** Professional Linux-style Terminal Interface built with the 'rich' library.
* **Audit Logging:** Saves results into timestamped CSV reports.

## 🛠️ Usage
```bash
# Run the master deployer
sudo ./scripts/vulnsense.sh
```

## 🧠 Technical Highlights
- **Engine:** Python 3.9+ / Scapy
- **UI:** Threaded Rendering with Rich Layouts
- **Math:** Shannon Entropy for 0-day tunnel detection.
