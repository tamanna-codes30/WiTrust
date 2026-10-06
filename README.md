# WiTrust

WiTrust is a prototype Wi-Fi security assistant.    

## What it does

1. Scans nearby Wi-Fi networks using Windows `netsh`.
2. Reads SSID, BSSID, signal, authentication, encryption, channel and band.
3. Applies simple, explainable risk rules.
4. Displays a LOW / MEDIUM / HIGH risk assessment.
5. Gives safety recommendations.
6. Reads the Windows ARP table for basic local-network device discovery.

## Run

Open Command Prompt or the VS Code terminal inside this folder:

```cmd
python main.py
```

No external Python packages are required.

## Requirements

- Windows
- Python 3.10+ (tested conceptually with Python 3.13)
- Working Wi-Fi adapter
- `netsh` available (standard on Windows)

## Optional tools

Nmap and Wireshark can be used later for deeper authorized network analysis, but they are not required for the MVP.

## Safety

Only scan or analyze networks and devices you own or have permission to test.

## Important limitation

The risk score is a prototype rule-based indicator. A HIGH result means the network has characteristics that deserve caution; it does not prove that a network is malicious.
