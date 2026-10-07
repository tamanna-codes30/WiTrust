import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from device_intelligence import DeviceHistoryStore, assess_device, fingerprint_device
from device_scanner import NmapScanner
from types import SimpleNamespace


class DeviceFingerprintTests(unittest.TestCase):
    def test_fingerprint_prefers_normalized_mac_for_stable_id(self):
        record = fingerprint_device({
            "mac": "02-11-22-33-44-55",
            "ip": "192.168.1.24",
            "hostname": "Laptop.local",
            "open_ports": ["443/tcp https (Example 1.2)"],
        }, {"ssid": "Office", "bssid": "00:11:22:33:44:66", "signal": "-54 dBm"})

        self.assertEqual(record["device_id"], "mac:02:11:22:33:44:55")
        self.assertEqual(record["open_ports"], ["443/tcp"])
        self.assertEqual(record["services"], ["https"])
        self.assertEqual(record["vendor"], "Unknown (not available)")
        self.assertEqual(record["ssid"], "Office")

    def test_fingerprint_falls_back_to_hostname_then_ip(self):
        self.assertEqual(fingerprint_device({"hostname": "Camera.local"})["device_id"], "host:camera.local")
        self.assertEqual(fingerprint_device({"ip": "192.168.1.8"})["device_id"], "ip:192.168.1.8")

    def test_incomplete_device_data_is_supported_and_unidentifiable_is_rejected(self):
        record = fingerprint_device({"ip": "192.168.1.8"})
        assessment = assess_device(record)
        self.assertEqual(assessment["risk_level"], "LOW")
        self.assertEqual(assessment["data_coverage_score"], 10)
        self.assertEqual(assessment["confidence"], 0.1)
        with self.assertRaises(ValueError):
            fingerprint_device({"ip": "not-an-ip"})


class DeviceTrustTests(unittest.TestCase):
    def test_first_observation_is_explained_and_assigns_new_device_risk(self):
        current = fingerprint_device({"ip": "192.168.1.12", "mac": "02:11:22:33:44:55"})
        assessment = assess_device(current, observed_at="2026-01-01T00:00:00+00:00")
        self.assertEqual(assessment["risk_score"], 10)
        self.assertEqual(assessment["trust_score"], 90)
        self.assertIsNone(assessment["trust_drift"])
        self.assertEqual(assessment["reasons"][0]["type"], "new_device")

    def test_new_ports_services_risky_service_and_trust_drift_are_reported(self):
        previous = {
            "device_id": "mac:02:11:22:33:44:55",
            "open_ports": ["80/tcp"],
            "services": ["http"],
            "trust_score": 95,
        }
        current = fingerprint_device({
            "mac": "02:11:22:33:44:55",
            "open_ports": ["80/tcp http", "23/tcp telnet"],
        })
        assessment = assess_device(current, previous)
        self.assertEqual(assessment["trust_drift"], -67)
        self.assertIn("23/tcp", assessment["new_ports"])
        self.assertIn("telnet", assessment["new_services"])
        self.assertIn("telnet_service", {reason["type"] for reason in assessment["reasons"]})
        self.assertEqual(assessment["risk_level"], "HIGH")

    def test_service_version_change_is_a_behavior_indicator(self):
        previous = {
            "device_id": "mac:02:11:22:33:44:55",
            "open_ports": ["443/tcp"],
            "services": ["https"],
            "service_details": ["443/tcp https (Example 1.0)"],
            "trust_score": 95,
        }
        current = fingerprint_device({
            "mac": "02:11:22:33:44:55",
            "open_ports": ["443/tcp https (Example 2.0)"],
            "ports_scanned": True,
        })
        assessment = assess_device(current, previous)
        self.assertEqual(assessment["changed_services"], ["443/tcp"])
        self.assertIn("service_changed", {reason["type"] for reason in assessment["reasons"]})

    def test_history_persists_ip_port_and_score_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DeviceHistoryStore(Path(directory) / "devices.sqlite3")
            first = store.observe(
                {"mac": "02:11:22:33:44:55", "ip": "192.168.1.12", "open_ports": ["80/tcp http"], "ports_scanned": True},
                observed_at="2026-01-01T00:00:00+00:00",
            )
            later = store.observe(
                {"mac": "02:11:22:33:44:55", "ip": "192.168.1.13", "open_ports": ["80/tcp http", "23/tcp telnet"], "ports_scanned": True},
                observed_at="2026-01-02T00:00:00+00:00",
            )
            history = store.get_history(first["device_id"])
            listed = store.list_devices()

        self.assertEqual(later["observation_count"], 2)
        self.assertEqual(later["first_seen"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(later["ip"], "192.168.1.13")
        self.assertEqual(later["trust_drift"], -62)
        self.assertEqual(len(history), 2)
        self.assertIn("23/tcp", history[0]["open_ports"])
        self.assertEqual(listed[0]["observation_count"], 2)

    def test_unscanned_ports_preserve_known_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DeviceHistoryStore(Path(directory) / "devices.sqlite3")
            store.observe({
                "mac": "02:11:22:33:44:55", "ip": "192.168.1.12",
                "open_ports": ["443/tcp https"], "ports_scanned": True,
            })
            refresh = store.observe({
                "mac": "02:11:22:33:44:55", "ip": "192.168.1.12",
                "interface": "ARP", "ports_scanned": False,
            })
        self.assertEqual(refresh["open_ports"], ["443/tcp"])
        self.assertEqual(refresh["services"], ["https"])

    def test_concurrent_observations_increment_history_without_losing_count(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DeviceHistoryStore(Path(directory) / "devices.sqlite3")
            device = {"mac": "02:11:22:33:44:55", "ip": "192.168.1.12"}
            with ThreadPoolExecutor(max_workers=6) as workers:
                list(workers.map(lambda _: store.observe(device), range(12)))
            listed = store.list_devices()
            history = store.get_history("mac:02:11:22:33:44:55")

        self.assertEqual(listed[0]["observation_count"], 12)
        self.assertEqual(len(history), 12)

    def test_legacy_history_records_get_coverage_derived_from_saved_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            store = DeviceHistoryStore(Path(directory) / "devices.sqlite3")
            observed = store.observe({"ip": "192.168.1.12"})
            with store._connection() as connection:
                assessment = {
                    key: value for key, value in observed.items()
                    if key in {"risk_score", "trust_score", "risk_level", "confidence", "reasons"}
                }
                connection.execute(
                    "UPDATE devices SET assessment_json = ? WHERE device_id = ?",
                    (json.dumps(assessment), observed["device_id"]),
                )
            self.assertEqual(store.list_devices()[0]["data_coverage_score"], 10)


class NmapFacadeTests(unittest.TestCase):
    def test_missing_nmap_does_not_prevent_device_intelligence_use(self):
        scanner = NmapScanner()
        with patch("device_scanner.find_nmap_executable", return_value=None):
            self.assertFalse(scanner.available)
            with self.assertRaisesRegex(RuntimeError, "Nmap was not found"):
                scanner.scan("192.168.1.0/24")
        record = fingerprint_device({"ip": "192.168.1.20"})
        self.assertEqual(assess_device(record)["risk_score"], 10)

    def test_detected_macos_subnet_uses_default_interface_netmask(self):
        route_result = SimpleNamespace(returncode=0, stdout="interface: en0\n")
        interface_result = SimpleNamespace(
            returncode=0,
            stdout="inet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255\n",
        )
        with (
            patch("device_scanner.sys.platform", "darwin"),
            patch("device_scanner.shutil.which", side_effect=lambda command: f"/usr/sbin/{command}"),
            patch("device_scanner.subprocess.run", side_effect=[route_result, interface_result]),
        ):
            self.assertEqual(NmapScanner.detect_target(), "192.168.1.0/24")


if __name__ == "__main__":
    unittest.main()
