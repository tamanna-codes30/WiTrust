import re
import subprocess
import ctypes
import time


def clean(value):
    return value.strip() if value else ""


def request_wifi_scan():
    """
    Ask Windows to perform a fresh Wi-Fi scan.
    """

    try:
        wlanapi = ctypes.WinDLL("wlanapi")

        # Open WLAN handle
        handle = ctypes.c_void_p()
        negotiated_version = ctypes.c_uint32()

        result = wlanapi.WlanOpenHandle(
            2,
            None,
            ctypes.byref(negotiated_version),
            ctypes.byref(handle)
        )

        if result != 0:
            return False

        # Get Wi-Fi interfaces
        interface_list = ctypes.c_void_p()

        result = wlanapi.WlanEnumInterfaces(
            handle,
            None,
            ctypes.byref(interface_list)
        )

        if result != 0:
            wlanapi.WlanCloseHandle(handle, None)
            return False

        # The first interface starts after:
        # 4 bytes = number of interfaces
        # 4 bytes = current index
        first_interface_address = interface_list.value + 8

        # GUID is the first field of WLAN_INTERFACE_INFO
        guid_pointer = ctypes.cast(
            first_interface_address,
            ctypes.POINTER(ctypes.c_byte)
        )

        result = wlanapi.WlanScan(
            handle,
            guid_pointer,
            None,
            None,
            None
        )

        wlanapi.WlanFreeMemory(interface_list)
        wlanapi.WlanCloseHandle(handle, None)

        if result != 0:
            return False

        return True

    except Exception:
        return False


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
    except Exception as e:
        raise RuntimeError(str(e))

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
            if current["bssid"] == "":
                current["bssid"] = clean(match.group(1))
                reading_first_bssid = True
            else:
                reading_first_bssid = False

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
    Perform a fresh Windows Wi-Fi scan and return nearby networks.
    """

    # Ask Windows to refresh the Wi-Fi scan
    request_wifi_scan()

    # Give Windows time to complete the scan
    time.sleep(5)

    # Read the updated results
    return get_networks_from_windows()

def get_connected_network():

    command = ["netsh", "wlan", "show", "interfaces"]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Windows could not get the connected Wi-Fi information."
        )

    lines = result.stdout.splitlines()

    network = {
        "ssid": "",
        "bssid": "",
        "signal": "",
        "authentication": "",
        "encryption": "",
        "channel": "",
        "band": ""
    }

    for line in lines:

        line = line.strip()

        if line.startswith("SSID") and not line.startswith("SSID name"):
            network["ssid"] = line.split(":", 1)[1].strip()

        elif line.startswith("AP BSSID"):
            network["bssid"] = line.split(":", 1)[1].strip()

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

    return network