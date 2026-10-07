import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path


WINDOWS_ARP_ENTRY = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})\s+\w+"
)
MACOS_ARP_ENTRY = re.compile(
    r"^\S*\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+"
    r"([0-9a-fA-F:]{17})\s+on\s+(\S+)"
)
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(block)
    for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _usable_device(ip_value, mac_value):
    try:
        address = ipaddress.IPv4Address(ip_value)
    except ipaddress.AddressValueError:
        return False

    mac = mac_value.replace("-", ":").lower()
    if (
        address.is_multicast or address.is_unspecified or address.is_loopback
        or address.is_reserved
    ):
        return False
    try:
        mac_octets = bytes.fromhex(mac.replace(":", ""))
    except ValueError:
        return False
    if len(mac_octets) != 6 or not any(mac_octets) or mac_octets[0] & 1:
        return False
    return True


def scan_devices():
    """Read discovered IPv4 devices from the local ARP cache."""
    command = ["arp", "-a"]
    if sys.platform == "darwin":
        command = ["arp", "-an"]

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
        raise RuntimeError("Local device discovery timed out.") from error
    except OSError as error:
        raise RuntimeError(str(error)) from error

    if result.returncode != 0:
        detail = result.stderr.strip() or "The system could not read its ARP table."
        raise RuntimeError(detail)

    devices = []
    seen_ips = set()
    current_interface = ""

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        interface_match = re.search(
            r"Interface:\s+(\d+\.\d+\.\d+\.\d+)",
            line,
            re.IGNORECASE,
        )
        if interface_match:
            current_interface = interface_match.group(1)
            continue

        macos_match = MACOS_ARP_ENTRY.match(line)
        if macos_match:
            ip_value, mac_value, interface = macos_match.groups()
        else:
            windows_match = WINDOWS_ARP_ENTRY.match(line)
            if not windows_match:
                continue
            ip_value, mac_value = windows_match.groups()
            interface = current_interface

        if not _usable_device(ip_value, mac_value) or ip_value in seen_ips:
            continue

        seen_ips.add(ip_value)
        devices.append({
            "ip": ip_value,
            "mac": mac_value.replace("-", ":").lower(),
            "interface": interface,
        })

    return devices


def validate_nmap_target(target):
    """Accept only small private IPv4 subnets for explicit LAN discovery."""
    try:
        network = ipaddress.ip_network(str(target).strip(), strict=False)
    except ValueError as error:
        raise ValueError("Enter a valid private IPv4 subnet, such as 192.168.1.0/24.") from error

    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Nmap discovery currently accepts IPv4 subnets only.")
    is_rfc1918 = any(network.subnet_of(private_network) for private_network in RFC1918_NETWORKS)
    if (
        not is_rfc1918
        or network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_reserved
        or network.num_addresses > 256
    ):
        raise ValueError(
            "For safety, enter an authorized private IPv4 subnet containing no more than 256 addresses."
        )
    return network


def parse_nmap_xml(output):
    """Parse Nmap XML into device records with hostnames and open TCP services."""
    try:
        root = ET.fromstring(output)
    except ET.ParseError as error:
        raise RuntimeError("Nmap returned invalid XML output.") from error

    devices = []
    seen_ips = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = next(
            (
                item.get("addr", "")
                for item in host.findall("address")
                if item.get("addrtype") == "ipv4"
            ),
            "",
        )
        try:
            ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError:
            continue
        if address in seen_ips:
            continue
        seen_ips.add(address)
        mac = next(
            (
                item.get("addr", "").replace("-", ":").lower()
                for item in host.findall("address")
                if item.get("addrtype") == "mac"
            ),
            "Unknown",
        )
        hostnames = [
            name.get("name", "").strip()
            for name in host.findall("hostnames/hostname")
            if name.get("name", "").strip()
        ]
        open_ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if port.get("protocol") != "tcp" or state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            service_name = service.get("name", "") if service is not None else ""
            service_version = " ".join(
                part for part in (
                    service.get("product", "") if service is not None else "",
                    service.get("version", "") if service is not None else "",
                ) if part
            )
            description = f"{port.get('portid', '?')}/tcp"
            if service_name:
                description += f" {service_name}"
            if service_version:
                description += f" ({service_version})"
            open_ports.append(description)

        devices.append({
            "ip": address,
            "mac": mac,
            "interface": "Nmap",
            "hostname": hostnames[0] if hostnames else "",
            "open_ports": open_ports,
        })
    return devices


def find_nmap_executable():
    """Locate Nmap in PATH or common installation directories."""
    executable = shutil.which("nmap")
    if executable:
        return executable

    candidates = [
        Path("/opt/homebrew/bin/nmap"),
        Path("/usr/local/bin/nmap"),
        Path("/usr/bin/nmap"),
    ]
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(Path(program_files) / "Nmap" / "nmap.exe")
    return next((str(candidate) for candidate in candidates if candidate.is_file()), None)


def detect_local_ipv4_subnet():
    """Return the active macOS default-route subnet when it is safely scannable."""
    if sys.platform != "darwin":
        return None
    route = shutil.which("route")
    ifconfig = shutil.which("ifconfig")
    if not route or not ifconfig:
        return None
    try:
        route_result = subprocess.run(
            [route, "-n", "get", "default"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=5, check=False,
        )
        if route_result.returncode:
            return None
        interface_match = re.search(r"^\s*interface:\s*(\S+)\s*$", route_result.stdout, re.MULTILINE)
        if not interface_match:
            return None
        interface_result = subprocess.run(
            [ifconfig, interface_match.group(1)], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=5, check=False,
        )
        address_match = re.search(
            r"^\s*inet\s+(\d+(?:\.\d+){3})\s+netmask\s+(0x[0-9a-fA-F]+|\d+(?:\.\d+){3})",
            interface_result.stdout,
            re.MULTILINE,
        )
        if interface_result.returncode or not address_match:
            return None
        address = ipaddress.IPv4Address(address_match.group(1))
        mask_value = address_match.group(2)
        netmask = ipaddress.IPv4Address(int(mask_value, 16)) if mask_value.startswith("0x") else ipaddress.IPv4Address(mask_value)
        network = ipaddress.IPv4Network(f"{address}/{netmask}", strict=False)
        if network.num_addresses > 256 or not any(network.subnet_of(item) for item in RFC1918_NETWORKS):
            return None
        return str(network)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


class NmapScanner:
    """Small facade keeping the rest of WiTrust independent of Nmap output."""

    @property
    def available(self):
        return find_nmap_executable() is not None

    @staticmethod
    def detect_target():
        return detect_local_ipv4_subnet()

    @staticmethod
    def parse_results(output):
        return parse_nmap_xml(output)

    def scan(self, target, profile="discovery", timeout=None, cancel_event=None):
        return scan_with_nmap(
            target, profile=profile, timeout=timeout, cancel_event=cancel_event
        )


def build_nmap_command(target, profile, executable="nmap"):
    """Build one of the bounded, non-scripted Nmap LAN scan profiles."""
    network = validate_nmap_target(target)
    if profile == "discovery":
        options = ["-sn"]
    elif profile == "common_tcp":
        options = ["-sT", "-sV", "--version-light", "--top-ports", "100", "-T3"]
    else:
        raise ValueError("Choose host discovery or common TCP service scan.")
    return [executable, *options, "-oX", "-", str(network)]


def _stop_nmap_process(process):
    if process.poll() is None:
        try:
            process.terminate()
        except OSError as error:
            if process.poll() is None:
                raise RuntimeError(f"Could not stop Nmap: {error}") from error
    try:
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError as error:
            if process.poll() is None:
                raise RuntimeError(f"Could not force-stop Nmap: {error}") from error
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Nmap did not stop after cancellation or timeout.") from error


def scan_with_nmap(target, profile="discovery", timeout=None, cancel_event=None):
    """Run bounded Nmap discovery or common TCP service detection.

    No UDP scans, OS fingerprinting, NSE scripts, or arbitrary port ranges are
    enabled. The optional event lets the GUI terminate an in-progress scan.
    """
    executable = find_nmap_executable()
    if not executable:
        raise RuntimeError(
            "Nmap was not found. Install Nmap from https://nmap.org/download.html, "
            "then reopen WiTrust."
        )
    command = build_nmap_command(target, profile, executable)
    timeout = timeout or (180 if profile == "common_tcp" else 120)
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        raise RuntimeError(f"Could not start Nmap: {error}") from error

    deadline = time.monotonic() + timeout
    while True:
        if cancel_event is not None and cancel_event.is_set():
            _stop_nmap_process(process)
            raise RuntimeError("Nmap scan was cancelled.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _stop_nmap_process(process)
            raise RuntimeError("Nmap scan timed out.")
        try:
            stdout, stderr = process.communicate(timeout=min(0.2, remaining))
            break
        except subprocess.TimeoutExpired:
            continue

    if process.returncode != 0:
        detail = stderr.strip() or "Nmap scan failed."
        raise RuntimeError(detail)
    return parse_nmap_xml(stdout)
