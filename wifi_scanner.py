import re
import subprocess
import ctypes
import time
import json
import sys
import shutil
import tempfile
from pathlib import Path


MAC_BRIDGE_SOURCE = Path(__file__).with_name("mac_wifi_bridge.swift")
MAC_BRIDGE_PLIST_SOURCE = Path(__file__).with_name("info.plist")
MAC_BRIDGE_APP = Path.home() / ".witrust" / "WiTrustLocation.app"
MAC_BRIDGE_CONTENTS = MAC_BRIDGE_APP / "Contents"
MAC_BRIDGE_INFO_PLIST = MAC_BRIDGE_CONTENTS / "Info.plist"
MAC_BRIDGE_BINARY = MAC_BRIDGE_CONTENTS / "MacOS" / "mac_wifi_bridge"


def _run_macos_bridge(action):
    """Compile the CoreWLAN helper when needed and run one Wi-Fi operation."""
    compiler = "/usr/bin/swiftc"
    if not Path(compiler).exists():
        raise RuntimeError(
            "The macOS Wi-Fi scanner needs Swift. Install Apple Command Line Tools with `xcode-select --install`."
        )

    try:
        if not MAC_BRIDGE_SOURCE.is_file() or not MAC_BRIDGE_PLIST_SOURCE.is_file():
            raise RuntimeError("The macOS Wi-Fi bridge source or info.plist is missing.")

        should_compile = (
            not MAC_BRIDGE_BINARY.exists()
            or MAC_BRIDGE_BINARY.stat().st_mtime < MAC_BRIDGE_SOURCE.stat().st_mtime
            or MAC_BRIDGE_BINARY.stat().st_mtime < MAC_BRIDGE_PLIST_SOURCE.stat().st_mtime
        )
        if should_compile:
            MAC_BRIDGE_BINARY.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(MAC_BRIDGE_PLIST_SOURCE, MAC_BRIDGE_INFO_PLIST)
            temporary_binary = MAC_BRIDGE_BINARY.with_suffix(".tmp")
            compilation = subprocess.run(
                [
                    compiler,
                    str(MAC_BRIDGE_SOURCE),
                    "-framework",
                    "CoreWLAN",
                    "-framework",
                    "CoreLocation",
                    "-framework",
                    "Foundation",
                    "-o",
                    str(temporary_binary),
                ],
                capture_output=True,
                text=True,
                timeout=90,
            )
            if compilation.returncode != 0:
                detail = compilation.stderr.strip() or compilation.stdout.strip()
                raise RuntimeError(f"Could not build the macOS Wi-Fi scanner: {detail}")
            temporary_binary.replace(MAC_BRIDGE_BINARY)
            signing = subprocess.run(
                ["/usr/bin/codesign", "--force", "--sign", "-", str(MAC_BRIDGE_APP)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if signing.returncode != 0:
                detail = signing.stderr.strip() or signing.stdout.strip()
                raise RuntimeError(f"Could not sign the macOS Wi-Fi scanner app: {detail}")

        with tempfile.TemporaryDirectory(prefix="witrust-scan-") as temporary_directory:
            output_path = Path(temporary_directory) / "result.json"
            error_path = Path(temporary_directory) / "error.txt"
            result = subprocess.run(
                [
                    "/usr/bin/open",
                    "-n",
                    "-W",
                    "-a",
                    str(MAC_BRIDGE_APP),
                    "--args",
                    action,
                    str(output_path),
                    str(error_path),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=75,
            )
            if error_path.exists():
                detail = error_path.read_text(encoding="utf-8", errors="replace").strip()
                if detail:
                    raise RuntimeError(detail)
            if result.returncode != 0:
                detail = result.stderr.strip() or "macOS could not access the Wi-Fi interface."
                raise RuntimeError(detail)
            if not output_path.exists():
                raise RuntimeError("The macOS Wi-Fi app did not return scan data.")
            output = output_path.read_text(encoding="utf-8")
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "The macOS Wi-Fi operation timed out. If a Location Services prompt "
            "is open, allow access and scan again. Otherwise confirm Wi-Fi is "
            "enabled and try again."
        ) from error
    except OSError as error:
        raise RuntimeError(str(error)) from error

    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError("The macOS Wi-Fi scanner returned invalid data.") from error


def clean(value):
    return value.strip() if value else ""


def request_wifi_scan():
    """
    Ask Windows to perform a fresh Wi-Fi scan.
    """

    wlanapi = None
    handle = ctypes.c_void_p()
    interface_list = ctypes.c_void_p()

    class GUID(ctypes.Structure):
        _fields_ = [
            ("data1", ctypes.c_uint32),
            ("data2", ctypes.c_uint16),
            ("data3", ctypes.c_uint16),
            ("data4", ctypes.c_ubyte * 8),
        ]

    try:
        wlanapi = ctypes.WinDLL("wlanapi")
        wlanapi.WlanOpenHandle.argtypes = [
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        wlanapi.WlanOpenHandle.restype = ctypes.c_uint32
        wlanapi.WlanEnumInterfaces.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        wlanapi.WlanEnumInterfaces.restype = ctypes.c_uint32
        wlanapi.WlanScan.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(GUID),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        wlanapi.WlanScan.restype = ctypes.c_uint32
        wlanapi.WlanFreeMemory.argtypes = [ctypes.c_void_p]
        wlanapi.WlanFreeMemory.restype = None
        wlanapi.WlanCloseHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        wlanapi.WlanCloseHandle.restype = ctypes.c_uint32

        negotiated_version = ctypes.c_uint32()
        if wlanapi.WlanOpenHandle(
            2, None, ctypes.byref(negotiated_version), ctypes.byref(handle)
        ) != 0:
            return False

        if wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(interface_list)) != 0:
            return False

        interface_count = ctypes.cast(
            interface_list, ctypes.POINTER(ctypes.c_uint32)
        ).contents.value
        if interface_count == 0:
            return False

        interface_guid = ctypes.cast(
            interface_list.value + 8, ctypes.POINTER(GUID)
        )
        return wlanapi.WlanScan(handle, interface_guid, None, None, None) == 0
    except (AttributeError, OSError, TypeError, ValueError):
        return False
    finally:
        if wlanapi is not None:
            if interface_list.value:
                wlanapi.WlanFreeMemory(interface_list)
            if handle.value:
                wlanapi.WlanCloseHandle(handle, None)


def get_networks_from_windows():
    """
    Read Wi-Fi networks from Windows using netsh.
    """

    command = [
        "netsh",
        "wlan",
        "show",
        "networks",
        "mode=bssid"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Wi-Fi scan timed out.")
    except OSError as error:
        raise RuntimeError(str(error)) from error

    if result.returncode != 0:
        raise RuntimeError(
            "Windows could not scan Wi-Fi networks."
        )

    lines = result.stdout.splitlines()

    networks = []
    current = None
    reading_first_bssid = False

    for raw in lines:
        line = raw.strip()

        # New Wi-Fi network
        match = re.match(
            r"SSID\s+\d+\s*:\s*(.*)",
            line,
            re.IGNORECASE
        )

        if match:
            if current is not None:
                networks.append(current)

            current = {
                "ssid": clean(match.group(1)),
                "bssid": "",
                "signal": "",
                "authentication": "",
                "encryption": "",
                "channel": "",
                "band": ""
            }

            reading_first_bssid = False
            continue

        if current is None:
            continue

        # Authentication
        match = re.match(
            r"Authentication\s*:\s*(.*)",
            line,
            re.IGNORECASE
        )

        if match:
            current["authentication"] = clean(match.group(1))
            continue

        # Encryption
        match = re.match(
            r"Encryption\s*:\s*(.*)",
            line,
            re.IGNORECASE
        )

        if match:
            current["encryption"] = clean(match.group(1))
            continue

        # BSSID
        match = re.match(
            r"BSSID\s+\d+\s*:\s*(.*)",
            line,
            re.IGNORECASE
        )

        if match:
            if current["bssid"]:
                networks.append(current)
                current = current.copy()
                current.update({
                    "bssid": "",
                    "signal": "",
                    "channel": "",
                    "band": "",
                })

            current["bssid"] = clean(match.group(1))
            reading_first_bssid = True

            continue

        if reading_first_bssid:

            # Signal
            match = re.match(
                r"Signal\s*:\s*(.*)",
                line,
                re.IGNORECASE
            )

            if match:
                current["signal"] = clean(match.group(1))
                continue

            # Channel
            match = re.match(
                r"Channel\s*:\s*(.*)",
                line,
                re.IGNORECASE
            )

            if match:
                current["channel"] = clean(match.group(1))
                continue

            # Band
            match = re.match(
                r"Band\s*:\s*(.*)",
                line,
                re.IGNORECASE
            )

            if match:
                current["band"] = clean(match.group(1))
                continue

    # Add last network
    if current is not None:
        networks.append(current)

    return networks


def scan_wifi():
    """
    Perform a fresh platform-native Wi-Fi scan and return nearby networks.
    """

    if sys.platform == "darwin":
        networks = _run_macos_bridge("scan")
        if not isinstance(networks, list):
            raise RuntimeError("The macOS Wi-Fi scanner returned an invalid network list.")
        if any(not isinstance(network, dict) for network in networks):
            raise RuntimeError("The macOS Wi-Fi scanner returned an invalid network entry.")
        if networks and all(not network.get("ssid") and not network.get("bssid") for network in networks):
            raise RuntimeError(
                "macOS is hiding Wi-Fi names and BSSIDs. Enable Location Services "
                "for WiTrust in System Settings > Privacy & Security > Location "
                "Services, then scan again. Permission for VS Code, Terminal, or "
                "Python alone does not grant WiTrust access."
            )
        return networks

    if sys.platform != "win32":
        raise RuntimeError("Wi-Fi scanning is supported on macOS and Windows.")

    # Windows completes WLAN scans asynchronously, so allow time for its
    # network list to settle instead of reading one potentially partial result.
    if not request_wifi_scan():
        raise RuntimeError(
            "Windows could not request a fresh Wi-Fi scan. Check that the WLAN "
            "AutoConfig service is running and that a Wi-Fi adapter is enabled."
        )

    started_at = time.monotonic()
    minimum_wait = 8
    maximum_wait = 20
    poll_interval = 2
    required_stable_reads = 3
    previous_signature = None
    stable_reads = 0
    networks = []
    best_networks = []

    while time.monotonic() - started_at < maximum_wait:
        networks = get_networks_from_windows()
        if len(networks) > len(best_networks):
            best_networks = networks
        signature = tuple(
            sorted(
                (
                    network.get("ssid", ""),
                    str(network.get("bssid") or "").casefold(),
                )
                for network in networks
            )
        )

        if signature and signature == previous_signature:
            stable_reads += 1
        else:
            stable_reads = 1 if signature else 0

        elapsed = time.monotonic() - started_at
        if elapsed >= minimum_wait and stable_reads >= required_stable_reads:
            return networks

        previous_signature = signature
        time.sleep(poll_interval)

    return best_networks

def get_connected_network():

    if sys.platform == "darwin":
        network = _run_macos_bridge("connected")
        if not isinstance(network, dict):
            raise RuntimeError("The macOS Wi-Fi scanner returned invalid connection details.")
        return network

    if sys.platform != "win32":
        raise RuntimeError("Connected Wi-Fi details are supported on macOS and Windows.")

    command = ["netsh", "wlan", "show", "interfaces"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Connected Wi-Fi lookup timed out.") from error
    except OSError as error:
        raise RuntimeError(str(error)) from error

    if result.returncode != 0:
        detail = result.stderr.strip() or "Windows could not get connected Wi-Fi information."
        raise RuntimeError(detail)

    lines = result.stdout.splitlines()

    network = {
        "ssid": "",
        "bssid": "",
        "connected": False,
        "signal": "",
        "authentication": "",
        "encryption": "",
        "channel": "",
        "band": ""
    }
    has_connection_state = False

    for line in lines:

        line = line.strip()

        if line.casefold().startswith("state"):
            state = line.split(":", 1)[-1].strip().casefold()
            network["connected"] = state == "connected"
            has_connection_state = True

        elif line.startswith("SSID") and not line.startswith("SSID name"):
            network["ssid"] = line.split(":", 1)[1].strip()

        elif re.match(r"(?:AP\s+)?BSSID\s*:", line, re.IGNORECASE):
            network["bssid"] = re.split(r":\s*", line, maxsplit=1)[1].strip()

        elif line.startswith("Signal"):
            network["signal"] = line.split(":", 1)[1].strip()

        elif line.startswith("Channel"):
            network["channel"] = line.split(":", 1)[1].strip()

        elif line.startswith("Band"):
            network["band"] = line.split(":", 1)[1].strip()

        elif line.startswith("Authentication"):
            network["authentication"] = line.split(":", 1)[1].strip()

        elif line.startswith("Cipher"):
            network["encryption"] = line.split(":", 1)[1].strip()

    if not has_connection_state:
        network["connected"] = bool(network["ssid"] or network["bssid"])
    elif not network["connected"]:
        for field in (
            "ssid", "bssid", "signal", "authentication", "encryption",
            "channel", "band",
        ):
            network[field] = ""

    return network
