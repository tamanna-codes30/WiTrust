import unittest
from io import BytesIO
from unittest.mock import Mock, PropertyMock, patch

import api_server


def handler(path, payload=None, origin="http://localhost:3000"):
    instance = object.__new__(api_server.WiTrustAPIHandler)
    instance.path = path
    instance.headers = {"Origin": origin}
    instance._read_json = Mock(return_value=payload or {})
    instance._send_json = Mock()
    return instance


class LocalApiTests(unittest.TestCase):
    def test_rejects_cross_origin_post_before_scanning(self):
        request = handler(
            "/api/devices/nmap",
            {"target": "192.168.1.0/24", "profile": "discovery", "authorized": True},
            origin="https://attacker.example",
        )
        with patch("api_server.NmapScanner.scan") as scan:
            request.do_POST()
        request._send_json.assert_called_once_with(
            403, {"error": "Origin is not allowed."}
        )
        scan.assert_not_called()

    def test_rejects_cross_origin_get(self):
        request = handler("/api/devices", origin="null")
        with patch("api_server.DeviceHistoryStore") as store:
            request.do_GET()
        request._send_json.assert_called_once_with(
            403, {"error": "Origin is not allowed."}
        )
        store.assert_not_called()

    def test_json_reader_requires_json_content_type(self):
        request = object.__new__(api_server.WiTrustAPIHandler)
        request.headers = {"Content-Length": "2", "Content-Type": "text/plain"}
        request.rfile = BytesIO(b"{}")
        with self.assertRaisesRegex(ValueError, "application/json"):
            request._read_json()

    def test_health_reports_service_status_without_network_scanning(self):
        request = handler("/api/health")
        with patch("api_server.NmapScanner.available", new_callable=PropertyMock, return_value=False):
            request.do_GET()
        request._send_json.assert_called_once_with(
            200, {"status": "ok", "service": "WiTrust", "nmap_available": False}
        )

    def test_wifi_scan_returns_backend_assessments(self):
        networks = [{
            "ssid": "Office",
            "bssid": "02:11:22:33:44:55",
            "authentication": "WPA2-Personal",
            "encryption": "CCMP",
        }]
        current = {**networks[0], "connected": True}
        request = handler("/api/wifi/scan", {})
        with (
            patch("api_server.scan_wifi", return_value=networks),
            patch("api_server._connected_record", return_value=current),
            patch("api_server._reputation_contexts", return_value=({}, {}, [None], "")),
        ):
            request.do_POST()
        status, body = request._send_json.call_args.args
        self.assertEqual(status, 200)
        self.assertEqual(body["networks"], networks)
        self.assertEqual(body["assessments"][0]["level"], "LOW")
        self.assertEqual(body["current_network"]["ssid"], "Office")

    def test_device_scan_returns_history_but_reports_current_observation_count(self):
        current_devices = [{"device_id": "mac:02:11:22:33:44:55"}]
        historical_inventory = [*current_devices, {"device_id": "ip:192.168.1.20"}]
        request = handler("/api/devices/scan")
        with (
            patch("api_server.scan_devices", return_value=[{"mac": "02:11:22:33:44:55"}]),
            patch("api_server._connected_record", return_value={}),
            patch("api_server.fingerprint_device", return_value={"device_id": current_devices[0]["device_id"]}),
            patch("api_server.DeviceHistoryStore") as store_type,
        ):
            store = store_type.return_value
            store.observe.return_value = current_devices[0]
            store.list_devices.return_value = historical_inventory
            request.do_POST()

        status, body = request._send_json.call_args.args
        self.assertEqual(status, 200)
        self.assertEqual(body["devices"], historical_inventory)
        self.assertEqual(body["observed_count"], 1)

    def test_nmap_requires_authorization_before_scanner_call(self):
        request = handler("/api/devices/nmap", {
            "target": "192.168.1.0/24", "profile": "discovery", "authorized": False,
        })
        with patch("api_server.NmapScanner.scan") as scan:
            request.do_POST()
        status, body = request._send_json.call_args.args
        self.assertEqual(status, 400)
        self.assertIn("authorization", body["error"].lower())
        scan.assert_not_called()

    def test_nmap_rejects_out_of_scope_target(self):
        request = handler("/api/devices/nmap", {
            "target": "8.8.8.0/24", "profile": "discovery", "authorized": True,
        })
        with patch("api_server.NmapScanner.scan") as scan:
            request.do_POST()
        status, body = request._send_json.call_args.args
        self.assertEqual(status, 400)
        self.assertIn("private ipv4", body["error"].lower())
        scan.assert_not_called()

    def test_unknown_endpoint_returns_not_found(self):
        request = handler("/api/not-a-route")
        request.do_GET()
        request._send_json.assert_called_once_with(404, {"error": "Endpoint not found."})


if __name__ == "__main__":
    unittest.main()
