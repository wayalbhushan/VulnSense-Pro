#!/bin/bash

# --- VulnSense Pro: Master Controller ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}==============================================${NC}"
echo -e "${BLUE}         VULNSENSE PRO: MASTER DEPLOYER       ${NC}"
echo -e "${BLUE}==============================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Error: sudo privileges required.${NC}"
   exit 1
fi

# Environment Setup
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    source .venv/bin/activate
    pip install scapy rich pandas psutil colorama --quiet
else
    source .venv/bin/activate
fi

# Argument Parsing
SAVE_FLAG=""
TARGET_IFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -s|--save) SAVE_FLAG="-s" ;;
        *) TARGET_IFACE=$1 ;;
    esac
    shift
done

echo -e "${GREEN}[+] Running Engine on ${TARGET_IFACE}...${NC}"
python3 vulnsense_pro.py -i "$TARGET_IFACE" $SAVE_FLAG