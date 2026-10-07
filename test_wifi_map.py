import unittest

from wifi_map import RISK_COLORS, build_wifi_map_layout, signal_proximity


class WifiMapTests(unittest.TestCase):
    def test_signal_strength_maps_to_relative_tiers(self):
        self.assertEqual(signal_proximity("-45 dBm"), "Nearer")
        self.assertEqual(signal_proximity("-65 dBm"), "Medium")
        self.assertEqual(signal_proximity("-82 dBm"), "Farther")
        self.assertEqual(signal_proximity("88%"), "Nearer")
        self.assertEqual(signal_proximity("unknown"), "Unknown")

    def test_layout_uses_signal_tiers_and_risk_colors(self):
        networks = [
            {"ssid": "Nearby", "signal": "-48 dBm"},
            {"ssid": "Far AP", "signal": "-84 dBm"},
        ]
        assessments = [
            {"score": 0, "level": "LOW"},
            {"score": 70, "level": "HIGH"},
        ]

        layout = build_wifi_map_layout(networks, assessments)
        nodes = {node["ssid"]: node for node in layout["nodes"]}

        self.assertEqual(nodes["Nearby"]["tier"], "Nearer")
        self.assertEqual(nodes["Nearby"]["color"], RISK_COLORS["LOW"])
        self.assertEqual(nodes["Far AP"]["tier"], "Farther")
        self.assertEqual(nodes["Far AP"]["color"], RISK_COLORS["HIGH"])
        self.assertLess(nodes["Nearby"]["radius"], nodes["Far AP"]["radius"])

    def test_layout_requires_matching_assessments(self):
        with self.assertRaisesRegex(ValueError, "matching risk assessment"):
            build_wifi_map_layout([{}], [])

    def test_critical_assessments_use_a_danger_color(self):
        layout = build_wifi_map_layout(
            [{"ssid": "Alert", "signal": "-50 dBm"}],
            [{"score": 90, "level": "CRITICAL"}],
        )
        self.assertEqual(layout["nodes"][0]["color"], RISK_COLORS["CRITICAL"])


if __name__ == "__main__":
    unittest.main()
