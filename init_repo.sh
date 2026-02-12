#!/bin/bash

# --- VulnSense Pro: GitHub Repository Initializer ---
echo -e "\e[34m[*] Initializing GitHub Repository Structure...\e[0m"

# 1. Create Folder Structure
mkdir -p core scripts assets docs

# 2. Move existing files to their professional locations
# Adjust names if your files are named differently
if [ -f "vulnsense_pro.py" ]; then
    mv vulnsense_pro.py core/
    echo -e "\e[32m[+] Moved engine to core/\e[0m"
fi

if [ -f "vulnsense.sh" ]; then
    mv vulnsense.sh scripts/
    chmod +x scripts/vulnsense.sh
    echo -e "\e[32m[+] Moved master deployer to scripts/\e[0m"
fi

# 3. Create requirements.txt
cat <<EOF > requirements.txt
scapy>=2.5.0
rich>=13.0.0
pandas>=2.0.0
psutil>=5.9.0
colorama>=0.4.6
EOF
echo -e "\e[32m[+] Created requirements.txt\e[0m"

# 4. Create .gitignore (To keep the repo clean)
cat <<EOF > .gitignore
.venv/
__pycache__/
*.csv
*.json
*.log
.DS_Store
EOF
echo -e "\e[32m[+] Created .gitignore\e[0m"

# 5. Create professional README.md
cat <<EOF > README.md
# VulnSense Pro v3.5 🛡️
**Enterprise-Grade Network Auditor & IDS with Real-time Entropy Analysis.**

VulnSense Pro is a security tool designed for real-time network auditing, credential leak detection, and DNS exfiltration monitoring. It features a professional Terminal User Interface (TUI) and uses mathematical entropy analysis to detect stealthy data exfiltration.

## 🚀 Key Features
* **DNS Exfiltration Detection:** Uses Shannon Entropy to identify high-randomness subdomains.
* **Credential Sniffer:** Monitors for plaintext JWTs, AWS Keys, and HTTP credentials.
* **TUI Dashboard:** Professional Linux-style Terminal Interface built with the 'rich' library.
* **Audit Logging:** Saves results into timestamped CSV reports.

## 🛠️ Usage
\`\`\`bash
# Run the master deployer
sudo ./scripts/vulnsense.sh
\`\`\`

## 🧠 Technical Highlights
- **Engine:** Python 3.9+ / Scapy
- **UI:** Threaded Rendering with Rich Layouts
- **Math:** Shannon Entropy for 0-day tunnel detection.
EOF
echo -e "\e[32m[+] Created README.md\e[0m"

# 6. Initialize Git (Optional - Uncomment if you want to start git immediately)
# git init
# git add .
# git commit -m "Initial commit: VulnSense Pro v3.5 Architecture"

echo -e "\e[36m\n[SUCCESS] Your GitHub repo is ready for staging!\e[0m"