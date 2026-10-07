import unittest

from evil_twin_detector import detect_evil_twins, get_multi_ap_info


def network(ssid, bssid, authentication, encryption="Encrypted"):
    return {
        "ssid": ssid,
        "bssid": bssid,
        "authentication": authentication,
        "encryption": encryption,
    }


class EvilTwinDetectorTests(unittest.TestCase):
    def test_flags_weaker_security_on_distinct_access_point(self):
        networks = [
            network("Office", "00:11:22:33:44:55", "WPA3"),
            network("Office", "00:11:22:33:44:66", "Open", "None"),
        ]

        findings = detect_evil_twins(networks)

        self.assertEqual(set(findings), {1})
        self.assertEqual(findings[1]["trusted_security"], "wpa3")

    def test_ssids_are_case_sensitive(self):
        networks = [
            network("Office", "00:11:22:33:44:55", "WPA3"),
            network("office", "00:11:22:33:44:66", "Open", "None"),
        ]

        self.assertEqual(detect_evil_twins(networks), {})

    def test_unknown_security_is_not_ranked_as_weaker(self):
        networks = [
            network("Office", "00:11:22:33:44:55", "WPA3"),
            network("Office", "00:11:22:33:44:66", "", ""),
        ]

        self.assertEqual(detect_evil_twins(networks), {})

    def test_conflicting_wpa_and_open_encryption_is_not_called_an_open_twin(self):
        networks = [
            network("Office", "00:11:22:33:44:55", "WPA3"),
            network("Office", "00:11:22:33:44:66", "WPA2-Personal", "None"),
        ]

        self.assertEqual(detect_evil_twins(networks), {})

    def test_multicast_bssids_are_not_used_as_access_point_identity(self):
        networks = [
            network("Office", "00:11:22:33:44:55", "WPA3"),
            network("Office", "01:11:22:33:44:66", "Open", "None"),
        ]

        self.assertEqual(detect_evil_twins(networks), {})

    def test_wpa3_transition_is_compatible_with_wpa2_access_point(self):
        networks = [
            network("Office", "00:11:22:33:44:55", "WPA3/WPA2 Personal"),
            network("Office", "00:11:22:33:44:66", "WPA2-Personal"),
        ]

        self.assertEqual(detect_evil_twins(networks), {})

    def test_requires_distinct_valid_bssids(self):
        networks = [
            network("Office", "00:11:22:33:44:55", "WPA3"),
            network("Office", "00:11:22:33:44:55", "Open", "None"),
            network("Office", "unknown", "Open", "None"),
        ]

        self.assertEqual(detect_evil_twins(networks), {})

    def test_duplicate_rows_do_not_inflate_multi_ap_count(self):
        networks = [
            network("Office", "00:11:22:33:44:55", "WPA2"),
            network("Office", "00-11-22-33-44-55", "WPA2"),
            network("Office", "00:11:22:33:44:66", "WPA2"),
        ]

        info = get_multi_ap_info(networks)

        self.assertEqual({entry["count"] for entry in info.values()}, {2})
        self.assertEqual(set(info), {0, 1, 2})

    def test_invalid_entries_are_ignored(self):
        networks = [
            None,
            {"ssid": 123, "bssid": "00:11:22:33:44:55"},
            network("Office", "00:11:22:33:44:66", "WPA3"),
        ]

        self.assertEqual(detect_evil_twins(networks), {})
        self.assertEqual(get_multi_ap_info(networks), {})


if __name__ == "__main__":
    unittest.main()
