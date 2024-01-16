# Network Security Scanner and SSH Bruteforce Tool

## Introduction

This Python script utilizes the Scapy library to perform a basic network security scan on a target IP or hostname. The scan checks for open ports and provides an option to perform an SSH bruteforce attack if port 22 is open.

## Prerequisites

- Python 3.x
- Scapy library
- Paramiko library

**Install the required libraries using:**

pip install scapy paramiko


#################

**Usage:**

1. Run the script:
    python main.py

2. Enter the target IP/hostname when prompted.
3. The script will check if the target is available by sending an ICMP ping.
4. If the target is available, it will perform a port scan on the first 80 ports.
4. Open ports will be displayed, and if port 22 (SSH) is open, you'll be prompted to perform an SSH bruteforce attack.
5. If you choose to run the bruteforce attack, the script will use a list of passwords from PasswordList.txt to attempt SSH authentication.

**Important Notes**

Make sure to have permission before scanning or attempting any security-related actions on a network.
The script uses a basic password list for the SSH bruteforce attack. Consider using a more extensive and secure password list for a real-world scenario. For example RockYou wordlist would be highly reccommended.

**Disclaimer**

⚠️ This script is intended for educational and ethical use only. Do not use it for any malicious purposes. The author is not responsible for any misuse or damage caused by this script.

