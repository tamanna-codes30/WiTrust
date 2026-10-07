"""Relative Wi-Fi proximity map helpers; positions are not geographic bearings."""

import math
import re


RISK_COLORS = {
    "LOW": "#168a35",
    "MEDIUM": "#d1a000",
    "HIGH": "#c62828",
    "CRITICAL": "#8f1238",
}
PROXIMITY_TIERS = ("Nearer", "Medium", "Farther", "Unknown")


def signal_proximity(signal):
    """Estimate a relative signal tier from RSSI (dBm) or reported percent."""
    if signal is None:
        return "Unknown"
    match = re.search(r"-?\d+(?:\.\d+)?", str(signal))
    if not match:
        return "Unknown"
    value = float(match.group())
    if "%" in str(signal):
        if not 0 <= value <= 100:
            return "Unknown"
        return "Nearer" if value >= 70 else "Medium" if value >= 35 else "Farther"
    if "dbm" in str(signal).casefold() or value < 0:
        if value > 0 or value < -120:
            return "Unknown"
        return "Nearer" if value >= -55 else "Medium" if value >= -72 else "Farther"
    return "Unknown"


def build_wifi_map_layout(networks, assessments, width=620, height=580):
    """Return drawing coordinates grouped by signal tier, never by direction."""
    if len(networks) != len(assessments):
        raise ValueError("Each network must have a matching risk assessment.")

    center_x = width / 2
    center_y = height / 2
    outer_radius = min(width, height) * 0.43
    tier_radii = {
        "Nearer": outer_radius * 0.30,
        "Medium": outer_radius * 0.55,
        "Farther": outer_radius * 0.80,
        "Unknown": outer_radius,
    }
    grouped = {tier: [] for tier in PROXIMITY_TIERS}
    for index, (network, assessment) in enumerate(zip(networks, assessments), start=1):
        tier = signal_proximity(network.get("signal"))
        grouped[tier].append({
            "index": index,
            "ssid": str(network.get("ssid") or "<Hidden SSID>"),
            "signal": str(network.get("signal") or "Unknown"),
            "score": assessment["score"],
            "level": assessment["level"],
            "color": RISK_COLORS.get(assessment["level"], "#687386"),
            "tier": tier,
        })

    nodes = []
    for tier, entries in grouped.items():
        count = len(entries)
        radius = tier_radii[tier]
        for position, entry in enumerate(entries):
            angle = -math.pi / 2 + 2 * math.pi * position / max(count, 1)
            nodes.append({
                **entry,
                "x": center_x + radius * math.cos(angle),
                "y": center_y + radius * math.sin(angle),
                "radius": radius,
            })

    return {
        "center": (center_x, center_y),
        "rings": [(tier, tier_radii[tier]) for tier in PROXIMITY_TIERS],
        "nodes": nodes,
    }
