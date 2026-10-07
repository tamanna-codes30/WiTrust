import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import device_scanner
import risk_engine
import wifi_reputation
import wifi_scanner
from main import WiTrustApp


class RiskEngineTests(unittest.TestCase):
    def test_open_network_with_suspicious_name_is_medium_risk(self):
        result = risk_engine.assess_network({
            "ssid": "Free_Cafe",
            "authentication": "Open",
            "encryption": "None",
        })

        self.assertEqual(result["score"], 35)
        self.assertEqual(result["level"], "MEDIUM")
        self.assertEqual(result["security_status"], "OPEN")
        self.assertTrue(result["observations"])

    def test_suspicious_ssid_words_do_not_add_risk_points(self):
        result = risk_engine.assess_network({
            "ssid": "Free_Cafe",
            "authentication": "WPA2-Personal",
            "encryption": "CCMP",
        })

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["data_quality"], "LOW")
        self.assertTrue(result["observations"])

    def test_wep_and_legacy_tkip_raise_risk(self):
        wep_result = risk_engine.assess_network({
            "authentication": "WEP",
            "encryption": "WEP",
        })
        tkip_result = risk_engine.assess_network({
            "authentication": "WPA2-Personal",
            "encryption": "TKIP",
        })

        self.assertEqual(wep_result["score"], 60)
        self.assertEqual(wep_result["level"], "HIGH")
        self.assertEqual(tkip_result["score"], 30)
        self.assertEqual(tkip_result["security_status"], "OUTDATED")
        tkip_signal = next(
            signal for signal in tkip_result["signals"]
            if signal["code"] == "legacy_tkip"
        )
        self.assertEqual(tkip_signal["points"], tkip_result["score"])

    def test_legacy_wpa_signal_points_match_score(self):
        result = risk_engine.assess_network({
            "authentication": "WPA-Personal",
            "encryption": "AES",
        })

        self.assertEqual(result["score"], 30)
        self.assertEqual(result["signals"], [{"code": "legacy_wpa", "points": 30}])

    def test_signal_and_channel_affect_coverage_not_threat_score(self):
        base = {
            "ssid": "Office",
            "bssid": "00:11:22:33:44:55",
            "authentication": "WPA2-Personal",
            "encryption": "CCMP",
        }
        complete = {
            **base,
            "signal": "-55 dBm",
            "channel": "36",
            "band": "5 GHz",
        }

        base_result = risk_engine.assess_network(base)
        complete_result = risk_engine.assess_network(complete)

        self.assertEqual(base_result["score"], complete_result["score"])
        self.assertEqual(base_result["data_coverage_score"], 80)
        self.assertEqual(complete_result["data_coverage_score"], 100)

    def test_evil_twin_and_reputation_context_raise_risk(self):
        network = {"ssid": "Office", "authentication": "WPA2", "encryption": "CCMP"}

        twin_result = risk_engine.assess_network(network, context={
            "evil_twin_finding": {"reason": "different security at second BSSID"}
        })
        reputation_result = risk_engine.assess_network(network, context={
            "reputation": {"status": "malicious", "source": "local list"}
        })

        self.assertEqual(twin_result["score"], 45)
        self.assertEqual(reputation_result["score"], 60)
        self.assertEqual(reputation_result["level"], "HIGH")

    def test_unknown_security_returns_low_data_quality(self):
        result = risk_engine.assess_network({"ssid": "Office"})

        self.assertEqual(result["security_status"], "UNKNOWN")
        self.assertEqual(result["data_quality"], "LOW")
        self.assertTrue(result["limitations"])

    def test_contradictory_wpa_and_open_encryption_is_not_called_protected(self):
        result = risk_engine.assess_network({
            "ssid": "Office",
            "bssid": "00:11:22:33:44:55",
            "authentication": "WPA2-Personal",
            "encryption": "None",
        })

        self.assertEqual(result["security_status"], "UNKNOWN")
        self.assertEqual(result["data_quality"], "LOW")
        self.assertIn(
            "conflicting_security_metadata",
            {signal["code"] for signal in result["signals"]},
        )

    def test_trusted_reputation_does_not_cancel_open_network_risk(self):
        result = risk_engine.assess_network(
            {"authentication": "Open", "encryption": "None"},
            context={"reputation": {"status": "trusted"}},
        )

        self.assertEqual(result["score"], 35)

    def test_app_assessment_context_uses_twin_and_local_reputation(self):
        app = WiTrustApp.__new__(WiTrustApp)
        app.evil_twin_findings = {0: {"reason": "weaker security than another BSSID"}}
        app.reputation_records = {
            "00:11:22:33:44:55": {"status": "malicious", "source": "test"}
        }
        network = {
            "ssid": "Office",
            "bssid": "00-11-22-33-44-55",
            "authentication": "WPA2",
            "encryption": "CCMP",
        }

        context = app.assessment_context(0, network)
        result = risk_engine.assess_network(network, context)

        self.assertEqual(result["score"], 100)
        self.assertEqual(
            {signal["code"] for signal in result["signals"]},
            {"evil_twin_indicator", "malicious_bssid"},
        )

    def test_wpa3_network_is_protected(self):
        result = risk_engine.assess_network({
            "authentication": "WPA3",
            "encryption": "Encrypted",
        })

        self.assertEqual(result["security_status"], "PROTECTED")
        self.assertEqual(result["score"], 0)

    def test_invalid_network_input_has_a_clear_error(self):
        with self.assertRaisesRegex(ValueError, "dictionary"):
            risk_engine.assess_network(None)

    def test_comparison_handles_connected_but_redacted_network(self):
        current = {
            "connected": True,
            "ssid": "",
            "ssid_redacted": True,
            "authentication": "WPA2",
            "encryption": "Encrypted",
        }

        result = risk_engine.compare_connected_network(current, [])

        self.assertTrue(any("withholding the network name" in line for line in result["comparison"]))
        self.assertFalse(any("No currently connected" in line for line in result["comparison"]))

    def test_comparison_assesses_each_network_once(self):
        current = {"ssid": "Home", "authentication": "WPA2"}
        nearby = [
            {"ssid": "Home", "authentication": "WPA2"},
            {"ssid": "Guest", "authentication": "Open", "encryption": "None"},
        ]
        with patch("risk_engine.assess_network", wraps=risk_engine.assess_network) as assess:
            risk_engine.compare_connected_network(current, nearby)

        self.assertEqual(assess.call_count, len(nearby) + 1)

    def test_comparison_uses_context_for_current_and_nearby_assessments(self):
        current = {
            "ssid": "Home",
            "bssid": "00-11-22-33-44-55",
            "authentication": "WPA2",
            "encryption": "CCMP",
        }
        nearby = [dict(current), {
            "ssid": "Guest",
            "bssid": "00:11:22:33:44:66",
            "authentication": "WPA2",
            "encryption": "CCMP",
        }]
        result = risk_engine.compare_connected_network(
            current,
            nearby,
            current_context={"reputation": {"status": "malicious"}},
            nearby_contexts=[
                {"reputation": {"status": "malicious"}},
                {"evil_twin_finding": {"reason": "test evidence"}},
            ],
        )

        self.assertEqual(result["current"]["score"], 60)
        self.assertTrue(any("higher risk score" in line for line in result["comparison"]))

    def test_comparison_rejects_mismatched_context_count(self):
        with self.assertRaisesRegex(ValueError, "matching assessment context"):
            risk_engine.compare_connected_network({}, [{}], nearby_contexts=[])


class ScannerTests(unittest.TestCase):
    def test_windows_connection_state_overrides_stale_network_fields(self):
        completed = SimpleNamespace(
            returncode=0,
            stdout="State : disconnected\nSSID : Previously connected\nAP BSSID : 00:11:22:33:44:55\n",
            stderr="",
        )
        with patch("wifi_scanner.sys.platform", "win32"), patch(
            "wifi_scanner.subprocess.run", return_value=completed
        ):
            network = wifi_scanner.get_connected_network()

        self.assertFalse(network["connected"])
        self.assertEqual(network["ssid"], "")
        self.assertEqual(network["bssid"], "")

    def test_windows_connection_state_identifies_a_current_connection(self):
        completed = SimpleNamespace(
            returncode=0,
            stdout="State : connected\nSSID : Office\nAP BSSID : 00:11:22:33:44:55\n",
            stderr="",
        )
        with patch("wifi_scanner.sys.platform", "win32"), patch(
            "wifi_scanner.subprocess.run", return_value=completed
        ):
            network = wifi_scanner.get_connected_network()

        self.assertTrue(network["connected"])
        self.assertEqual(network["ssid"], "Office")
        self.assertEqual(network["bssid"], "00:11:22:33:44:55")

    def test_windows_scan_does_not_return_cached_results_when_refresh_fails(self):
        with patch("wifi_scanner.sys.platform", "win32"), patch(
            "wifi_scanner.request_wifi_scan", return_value=False
        ), patch("wifi_scanner.get_networks_from_windows") as read_cached:
            with self.assertRaisesRegex(RuntimeError, "fresh Wi-Fi scan"):
                wifi_scanner.scan_wifi()
        read_cached.assert_not_called()

    def test_windows_scan_keeps_largest_snapshot_if_results_never_stabilize(self):
        best_snapshot = [
            {"ssid": "Office", "bssid": "00:11:22:33:44:55"},
            {"ssid": "Guest", "bssid": "00:11:22:33:44:66"},
        ]
        with (
            patch("wifi_scanner.sys.platform", "win32"),
            patch("wifi_scanner.request_wifi_scan", return_value=True),
            patch("wifi_scanner.get_networks_from_windows", side_effect=[best_snapshot, *([[]] * 10)]),
            patch("wifi_scanner.time.monotonic", side_effect=iter(range(100))),
            patch("wifi_scanner.time.sleep"),
        ):
            networks = wifi_scanner.scan_wifi()

        self.assertEqual(networks, best_snapshot)

    def test_nmap_accepts_small_private_subnet_and_rejects_public_or_large_target(self):
        self.assertEqual(
            str(device_scanner.validate_nmap_target("192.168.1.0/24")),
            "192.168.1.0/24",
        )
        for target in (
            "8.8.8.0/24",
            "10.0.0.0/16",
            "192.0.2.0/24",
            "not-a-subnet",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                device_scanner.validate_nmap_target(target)

    def test_nmap_xml_parser_returns_only_up_ipv4_hosts(self):
        output = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA-BB-CC-DD-EE-FF" addrtype="mac"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports><port protocol="tcp" portid="443"><state state="open"/>
      <service name="https" product="Example Server" version="1.0"/>
    </port><port protocol="tcp" portid="23"><state state="closed"/>
      <service name="telnet"/>
    </port></ports>
  </host>
  <host><status state="down"/><address addr="192.168.1.2" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="192.168.1.3" addrtype="ipv4"/></host>
</nmaprun>"""
        self.assertEqual(device_scanner.parse_nmap_xml(output), [
            {
                "ip": "192.168.1.1",
                "mac": "aa:bb:cc:dd:ee:ff",
                "interface": "Nmap",
                "hostname": "router.local",
                "open_ports": ["443/tcp https (Example Server 1.0)"],
            },
            {
                "ip": "192.168.1.3",
                "mac": "Unknown",
                "interface": "Nmap",
                "hostname": "",
                "open_ports": [],
            },
        ])

    def test_nmap_profiles_are_bounded_and_do_not_enable_scripts(self):
        discovery = device_scanner.build_nmap_command(
            "192.168.1.0/24", "discovery", "/usr/bin/nmap"
        )
        services = device_scanner.build_nmap_command(
            "192.168.1.0/24", "common_tcp", "/usr/bin/nmap"
        )
        self.assertIn("-sn", discovery)
        self.assertIn("-sT", services)
        self.assertIn("--top-ports", services)
        self.assertIn("100", services)
        self.assertIn("--version-light", services)
        self.assertNotIn("-n", discovery)
        self.assertNotIn("-n", services)
        self.assertFalse(any(argument.startswith("--script") for argument in services))

    def test_nmap_runs_discovery_and_returns_parsed_hosts(self):
        process = SimpleNamespace(
            returncode=0,
            communicate=lambda **_kwargs: ("<nmaprun/>", ""),
        )
        with patch("device_scanner.find_nmap_executable", return_value="/usr/bin/nmap"), patch(
            "device_scanner.subprocess.Popen", return_value=process
        ) as popen:
            devices = device_scanner.scan_with_nmap("192.168.1.0/24")

        self.assertEqual(devices, [])
        self.assertEqual(popen.call_args.args[0], [
            "/usr/bin/nmap", "-sn", "-oX", "-", "192.168.1.0/24"
        ])

    def test_nmap_scan_can_be_cancelled(self):
        terminated = []
        process = SimpleNamespace(
            returncode=-15,
            communicate=lambda **_kwargs: ("", ""),
            poll=lambda: None,
            terminate=lambda: terminated.append(True),
        )
        cancel_event = threading.Event()
        cancel_event.set()
        with patch("device_scanner.find_nmap_executable", return_value="nmap"), patch(
            "device_scanner.subprocess.Popen", return_value=process
        ):
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                device_scanner.scan_with_nmap(
                    "192.168.1.0/24", cancel_event=cancel_event
                )
        self.assertEqual(terminated, [True])

    def test_windows_parser_keeps_each_access_point(self):
        output = """SSID 1 : Office
    Authentication : WPA2-Personal
    Encryption : CCMP
    BSSID 1 : 00:11:22:33:44:55
         Signal : 80%
         Channel : 36
         Band : 5 GHz
    BSSID 2 : 00:11:22:33:44:66
         Signal : 60%
         Channel : 44
         Band : 5 GHz
SSID 2 : Guest
    Authentication : Open
    Encryption : None
    BSSID 1 : 10:11:22:33:44:55
         Signal : 42%
"""
        completed = SimpleNamespace(returncode=0, stdout=output, stderr="")
        with patch("wifi_scanner.subprocess.run", return_value=completed):
            networks = wifi_scanner.get_networks_from_windows()

        self.assertEqual(len(networks), 3)
        self.assertEqual(networks[0]["ssid"], "Office")
        self.assertEqual(networks[1]["bssid"], "00:11:22:33:44:66")
        self.assertEqual(networks[1]["channel"], "44")
        self.assertEqual(networks[2]["ssid"], "Guest")

    def test_macos_redaction_is_reported_as_permission_issue(self):
        redacted_networks = [{"ssid": "", "bssid": "", "signal": "-55 dBm"}]
        with patch("wifi_scanner.sys.platform", "darwin"), patch(
            "wifi_scanner._run_macos_bridge", return_value=redacted_networks
        ):
            with self.assertRaisesRegex(RuntimeError, "Location Services"):
                wifi_scanner.scan_wifi()

    def test_windows_arp_output_is_parsed_and_filtered(self):
        output = """Interface: 192.168.1.10 --- 0x8
  192.168.1.1          00-11-22-33-44-55     dynamic
  224.0.0.1            01-00-5e-00-00-01     static
  192.168.1.20         incomplete             dynamic
"""
        completed = SimpleNamespace(returncode=0, stdout=output, stderr="")
        with patch("device_scanner.sys.platform", "win32"), patch(
            "device_scanner.subprocess.run", return_value=completed
        ) as run:
            devices = device_scanner.scan_devices()

        run.assert_called_once_with(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        self.assertEqual(devices, [{
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "interface": "192.168.1.10",
        }])

    def test_arp_filter_rejects_reserved_ip_and_any_multicast_mac(self):
        self.assertFalse(device_scanner._usable_device("255.255.255.255", "00:11:22:33:44:55"))
        self.assertFalse(device_scanner._usable_device("192.168.1.10", "01:80:c2:00:00:01"))

    def test_macos_arp_output_is_parsed(self):
        output = "? (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]\n"
        completed = SimpleNamespace(returncode=0, stdout=output, stderr="")
        with patch("device_scanner.sys.platform", "darwin"), patch(
            "device_scanner.subprocess.run", return_value=completed
        ):
            devices = device_scanner.scan_devices()

        self.assertEqual(devices[0]["interface"], "en0")


class ReputationTests(unittest.TestCase):
    def test_reputation_persists_and_marks_malicious_bssid_high(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "reputation.json"
            wifi_reputation.set_reputation(
                "00:11:22:33:44:55",
                "malicious",
                reason="Test indicator",
                path=database_path,
            )
            database = wifi_reputation.load_database(database_path)
            result = wifi_reputation.assess_reputation(
                {"bssid": "00:11:22:33:44:55", "authentication": "WPA2"},
                database,
            )

        self.assertEqual(result["score"], 60)
        self.assertEqual(result["level"], "HIGH")
        self.assertEqual(result["signals"][0]["code"], "malicious_bssid")
        engine_result = risk_engine.assess_network(
            {"bssid": "00:11:22:33:44:55", "authentication": "WPA2"},
            context={"reputation": {"status": "malicious"}},
        )
        self.assertEqual(result["score"], engine_result["score"])

    def test_invalid_database_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "reputation.json"
            database_path.write_text(json.dumps({"networks": {"bad": "entry"}}))

            with self.assertRaisesRegex(ValueError, "invalid network entry"):
                wifi_reputation.load_database(database_path)

    def test_feed_requires_network_list(self):
        with tempfile.TemporaryDirectory() as directory:
            feed_path = Path(directory) / "feed.json"
            database_path = Path(directory) / "reputation.json"
            feed_path.write_text(json.dumps({"version": 1}))

            with self.assertRaisesRegex(ValueError, "networks"):
                wifi_reputation.import_feed(feed_path, database_path)


if __name__ == "__main__":
    unittest.main()
