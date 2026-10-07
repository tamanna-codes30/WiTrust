"""Loopback-only JSON API adapter for the existing WiTrust Python modules."""

from __future__ import annotations

import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime
from urllib.parse import unquote, urlsplit

from device_intelligence import DeviceHistoryStore, fingerprint_device
from device_scanner import NmapScanner, scan_devices, validate_nmap_target
from evil_twin_detector import detect_evil_twins
from risk_engine import assess_network, compare_connected_network
from wifi_reputation import load_database, normalize_bssid
from wifi_scanner import get_connected_network, scan_wifi


LOGGER = logging.getLogger("witrust.api")
MAX_REQUEST_BYTES = 64 * 1024
ALLOWED_ORIGINS = {
    "http://localhost:3000",
    "http://127.0.0.1:3000",
}


def _connected_record():
    network = get_connected_network()
    network.setdefault("connected", bool(network.get("ssid") or network.get("bssid")))
    return network


def _reputation_contexts(networks):
    findings = detect_evil_twins(networks)
    try:
        records = load_database()["networks"]
        warning = ""
    except ValueError as error:
        records = {}
        warning = f"Local reputation data unavailable: {error}"
    contexts = []
    for index, network in enumerate(networks):
        context = {}
        if index in findings:
            context["evil_twin_finding"] = findings[index]
        reputation = records.get(normalize_bssid(network.get("bssid")))
        if reputation:
            context["reputation"] = reputation
        contexts.append(context or None)
    return findings, records, contexts, warning


class WiTrustAPIHandler(BaseHTTPRequestHandler):
    server_version = "WiTrustLocalAPI/1.0"

    def log_message(self, _format, *_args):
        return

    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("Content-Length must be an integer.") from error
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("Request body is too large.")
        if not length:
            return {}
        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().casefold() != "application/json":
            raise ValueError("Content-Type must be application/json.")
        try:
            payload = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Request body must be valid JSON.") from error
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        if origin not in ALLOWED_ORIGINS:
            self._send_json(403, {"error": "Origin is not allowed."})
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Vary", "Origin")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        origin = self.headers.get("Origin")
        if origin is not None and origin not in ALLOWED_ORIGINS:
            self._send_json(403, {"error": "Origin is not allowed."})
            return
        route = urlsplit(self.path).path
        try:
            if route == "/api/health":
                self._send_json(200, {"status": "ok", "service": "WiTrust", "nmap_available": NmapScanner().available})
            elif route == "/api/wifi/current":
                self._send_json(200, {"network": _connected_record()})
            elif route == "/api/nmap/target":
                self._send_json(200, {"target": NmapScanner.detect_target()})
            elif route == "/api/devices":
                self._send_json(200, {"devices": DeviceHistoryStore().list_devices()})
            elif route.startswith("/api/devices/") and route.endswith("/history"):
                device_id = unquote(route[len("/api/devices/"):-len("/history")].strip("/"))
                self._send_json(200, {"history": DeviceHistoryStore().get_history(device_id)})
            else:
                self._send_json(404, {"error": "Endpoint not found."})
        except (OSError, RuntimeError, ValueError) as error:
            self._send_json(503, {"error": str(error)})
        except Exception:
            LOGGER.exception("Unexpected local API GET failure")
            self._send_json(500, {"error": "The local WiTrust API encountered an unexpected error."})

    def do_POST(self):
        origin = self.headers.get("Origin")
        if origin is not None and origin not in ALLOWED_ORIGINS:
            self._send_json(403, {"error": "Origin is not allowed."})
            return
        route = urlsplit(self.path).path
        try:
            payload = self._read_json()
            if route == "/api/wifi/scan":
                self._scan_wifi()
            elif route == "/api/wifi/compare":
                self._compare_wifi()
            elif route == "/api/devices/scan":
                self._scan_devices()
            elif route == "/api/devices/nmap":
                self._scan_nmap(payload)
            else:
                self._send_json(404, {"error": "Endpoint not found."})
        except ValueError as error:
            self._send_json(400, {"error": str(error)})
        except (OSError, RuntimeError) as error:
            self._send_json(502, {"error": str(error)})
        except Exception:
            LOGGER.exception("Unexpected local API POST failure")
            self._send_json(500, {"error": "The local WiTrust API encountered an unexpected error."})

    def _scan_wifi(self):
        current_network = None
        current_error = ""
        try:
            current_network = _connected_record()
        except (OSError, RuntimeError) as error:
            current_error = str(error)
        networks = scan_wifi()
        findings, _records, contexts, warning = _reputation_contexts(networks)
        assessments = [
            assess_network(network, context=context)
            for network, context in zip(networks, contexts)
        ]
        current_assessment = None
        if current_network and current_network.get("connected"):
            current_bssid = normalize_bssid(current_network.get("bssid"))
            current_index = next((
                index for index, network in enumerate(networks)
                if current_bssid and normalize_bssid(network.get("bssid")) == current_bssid
            ), None)
            current_context = contexts[current_index] if current_index is not None else None
            if current_context is None and current_bssid in _records:
                current_context = {"reputation": _records[current_bssid]}
            current_assessment = assess_network(current_network, context=current_context)
        self._send_json(200, {
            "networks": networks,
            "assessments": assessments,
            "findings": findings,
            "current_network": current_network,
            "current_assessment": current_assessment,
            "current_error": current_error,
            "warning": warning,
            "scanned_at": datetime.now().astimezone().isoformat(),
        })

    def _compare_wifi(self):
        current = _connected_record()
        networks = scan_wifi()
        findings, records, contexts, _warning = _reputation_contexts(networks)
        current_bssid = normalize_bssid(current.get("bssid"))
        current_index = next((
            index for index, network in enumerate(networks)
            if current_bssid and normalize_bssid(network.get("bssid")) == current_bssid
        ), None)
        current_context = contexts[current_index] if current_index is not None else None
        if current_context is None and current_bssid in records:
            current_context = {"reputation": records[current_bssid]}
        result = compare_connected_network(
            current,
            networks,
            current_context=current_context,
            nearby_contexts=contexts,
        )
        self._send_json(200, {
            "result": result,
            "networks": networks,
            "findings": findings,
        })

    def _scan_devices(self):
        devices = scan_devices()
        try:
            network = _connected_record()
        except (OSError, RuntimeError):
            network = None
        store = DeviceHistoryStore()
        records = []
        observed_ids = set()
        for device in devices:
            device = {**device, "ports_scanned": False}
            device_id = fingerprint_device(device, network)["device_id"]
            if device_id in observed_ids:
                continue
            records.append(store.observe(device, network))
            observed_ids.add(device_id)
        self._send_json(200, {
            "devices": store.list_devices(),
            "observed_count": len(records),
            "source": "ARP",
            "scanned_at": datetime.now().astimezone().isoformat(),
        })

    def _scan_nmap(self, payload):
        if payload.get("authorized") is not True:
            raise ValueError("Confirm authorization before starting an Nmap scan.")
        target = str(payload.get("target", ""))
        profile = str(payload.get("profile", "common_tcp"))
        validate_nmap_target(target)
        if profile not in {"discovery", "common_tcp"}:
            raise ValueError("Choose a supported Nmap scan profile.")
        devices = NmapScanner().scan(target, profile=profile)
        try:
            network = _connected_record()
        except (OSError, RuntimeError):
            network = None
        store = DeviceHistoryStore()
        records = []
        seen = set()
        for device in devices:
            device = {**device, "ports_scanned": profile == "common_tcp"}
            device_id = fingerprint_device(device, network)["device_id"]
            if device_id in seen:
                continue
            records.append(store.observe(device, network))
            seen.add(device_id)
        self._send_json(200, {
            "devices": store.list_devices(),
            "observed_count": len(records),
            "source": "Nmap",
            "profile": profile,
            "scanned_at": datetime.now().astimezone().isoformat(),
        })


class LocalThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the WiTrust local API on loopback.")
    parser.add_argument("--port", type=int, default=8765)
    arguments = parser.parse_args(argv)
    if not 1024 <= arguments.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    server = LocalThreadingHTTPServer(("127.0.0.1", arguments.port), WiTrustAPIHandler)
    print(f"WiTrust API listening on http://127.0.0.1:{arguments.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping WiTrust API.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
