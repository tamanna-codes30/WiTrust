# WiTrust

WiTrust is a prototype Wi-Fi security assistant.

## What it does

1. Scans nearby Wi-Fi networks using Apple CoreWLAN on macOS or Windows `netsh`.
2. Reads SSID, BSSID, signal, authentication, encryption, channel and band.
3. Applies simple, explainable risk rules.
4. Displays a LOW / MEDIUM / HIGH risk assessment.
5. Gives safety recommendations.
6. Reads the local ARP table for basic network-device discovery.
7. Builds local device fingerprints, keeps observation history in SQLite, and explains device trust/risk changes.

Risk scoring considers reported authentication/encryption, legacy WEP/WPA/TKIP, conflicting security metadata, evil-twin indicators, and local malicious-BSSID reputation. The desktop app and reputation CLI use the same scoring engine. Each assessment exposes its score signals and a separate data-coverage percentage based on available SSID, BSSID, security, signal, channel, and band fields; coverage is field completeness, not a probability of correctness. Signal strength, channel, band, SSID wording, and trusted labels do not independently lower or raise threat risk. These are heuristic indicators, not proof that a network is malicious.

## Run

Open a terminal inside this folder:

```sh
python3 main.py
```

No external Python packages are required.

## Web frontend

The repository contains no pre-existing HTTP API, so `api_server.py` provides a small loopback-only adapter over the existing Python scanning, scoring, reputation, Nmap, and SQLite history modules. It binds only to `127.0.0.1`; Nmap still requires explicit authorization and a bounded private IPv4 CIDR.

Start the local API in one terminal:

```sh
python3 api_server.py
```

Start the Next.js frontend in a second terminal:

```sh
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`. The web app proxies `/api/*` to `http://127.0.0.1:8765`. To use another local API port/origin, create `frontend/.env.local` from `.env.example` and set `WITRUST_API_URL` before starting Next.js. The frontend uses Next.js App Router, React, TypeScript, and Tailwind CSS; no mock scan results are shown when the backend is unavailable.

## Requirements

- Python 3.10+ with Tcl/Tk 8.6 or later for the desktop interface.
- Working Wi-Fi adapter
- Windows: `netsh` is included with Windows.
- macOS: install Apple Command Line Tools (`xcode-select --install`) so the app can build and sign its small CoreWLAN app bundle on first scan. The helper is cached under `~/.witrust/`.

On macOS, Wi-Fi names and BSSIDs are available to CoreWLAN only when Location Services is enabled and authorized. On the first scan, allow **WiTrust** in System Settings > Privacy & Security > Location Services. Permission for the launcher (such as VS Code, Terminal, or Python) is not sufficient. Without access, scans may return results with blank names and BSSIDs; WiTrust reports this as a permission issue instead of showing them as hidden networks or disconnected. Device discovery reads the system ARP cache, which only includes devices your Mac has recently communicated with.

Check the GUI toolkit version with `python3 -c 'import tkinter; print(tkinter.Tcl().eval("info patchlevel"))'`; it must report 8.6 or later. If it is older, use a Python installation with a newer Tcl/Tk build.

## Tests

Run the hardware-independent regression suite with:

```sh
python3 -m unittest discover -v
```

The `test_connection.py` and `test_comparison.py` scripts are optional live checks; run them directly only when you want to query the local Wi-Fi interface.

## Optional tools

Nmap is optional. Install it from [nmap.org/download.html](https://nmap.org/download.html) and reopen WiTrust. Click **Scan Local Devices**, then **Run Nmap Assessment**. On macOS WiTrust attempts to detect the active default-route private subnet (up to 256 addresses); otherwise enter a subnet manually. Confirm authorization before scanning. Choose **Host discovery only** (`-sn`) or **Common TCP ports + light service detection** (`-sT -sV --version-light --top-ports 100`). The service profile does not scan UDP, detect operating systems, or run vulnerability scripts. Scans run in the background and can be cancelled. If Nmap is absent, ARP discovery and device history remain available. Use Nmap only on networks you own or have permission to assess.

## Device intelligence

The device panel combines ARP observations and optional Nmap results. Device IDs prefer normalized MAC addresses, then hostname, then IP. History is stored locally at `~/.witrust/device_history.sqlite3`; no cloud service or added Python packages are used. Select a device to see first/last observation, services, machine-readable score reasons, history, and trust drift. **Threat Graph** displays local-network relationships; placement is illustrative, not physical distance. Service and vendor data may be unavailable from ARP or on platforms without those fields. An ARP refresh does not erase ports from the last Nmap service scan. The inventory keeps devices from prior observations and shows their last-seen time; the scan count reports only devices returned by the latest scan.

Device trust is a transparent heuristic (`trust = 100 - risk`), with weights centralized in `device_intelligence.py`. A first observation, newly detected ports/services, and selected exposed legacy services add risk; previously observed stable devices receive small offsets. Trust drift is the current trust score minus the previous observation's score. Evidence coverage is the percentage of ten device/network/service fields available in a record. The API's `confidence` compatibility field mirrors this normalized completeness and is not a calibrated probability. A score is not proof of compromise; investigate high-risk devices and verify authorization before taking action.

## Safety

Only scan or analyze networks and devices you own or have permission to test.

## Important limitation

The risk score is a prototype rule-based indicator. A HIGH result means the network has characteristics that deserve caution; it does not prove that a network is malicious.
