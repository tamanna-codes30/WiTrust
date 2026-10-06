import subprocess
import re


def scan_devices():

    devices = []

    try:

        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

    except Exception as e:

        raise RuntimeError(str(e))


    lines = result.stdout.splitlines()

    current_interface = ""

    for line in lines:

        line = line.strip()


        # Get interface IP
        interface_match = re.search(
            r"Interface:\s+(\d+\.\d+\.\d+\.\d+)",
            line,
            re.IGNORECASE
        )


        if interface_match:

            current_interface = interface_match.group(1)

            continue


        # Get IP and MAC
        match = re.match(
            r"(\d+\.\d+\.\d+\.\d+)\s+"
            r"([0-9a-fA-F-]{17})\s+\w+",
            line
        )


        if not match:

            continue


        ip = match.group(1)

        mac = match.group(2).lower()


        # Ignore broadcast addresses

        if ip.endswith(".255"):

            continue


        # Ignore multicast addresses

        if ip.startswith("224."):

            continue

        if ip.startswith("239."):

            continue


        # Ignore general broadcast

        if ip == "255.255.255.255":

            continue


        # Ignore broadcast MAC

        if mac == "ff-ff-ff-ff-ff-ff":

            continue


        # Ignore multicast MAC

        if mac.startswith("01-00-5e"):

            continue


        # Avoid duplicate devices

        already_found = False

        for device in devices:

            if device["ip"] == ip:

                already_found = True

                break


        if already_found:

            continue


        devices.append({
            "ip": ip,
            "mac": mac,
            "interface": current_interface
        })


    return devices