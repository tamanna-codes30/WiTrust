"""Identify suspicious security differences among access points sharing an SSID."""

import re


_BSSID_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)
_SECURITY_PRIORITY = {
    "open": 0,
    "wep": 1,
    "wpa": 2,
    "wpa2": 3,
    "wpa3": 4,
}


def _normalise(value):
    return value.strip().casefold() if isinstance(value, str) else ""


def _normalise_bssid(value):
    candidate = _normalise(value).replace("-", ":")
    if not _BSSID_PATTERN.fullmatch(candidate):
        return ""
    octets = bytes.fromhex(candidate.replace(":", ""))
    if not any(octets) or all(octet == 0xFF for octet in octets) or octets[0] & 1:
        return ""
    return candidate


def _security(network):
    authentication = _normalise(network.get("authentication"))
    encryption = _normalise(network.get("encryption"))

    if "wep" in authentication or "wep" in encryption:
        return "wep"
    if authentication in {"open", "none"}:
        return "open"
    if any(protocol in authentication for protocol in ("wpa3", "wpa2", "wpa")):
        if encryption in {"none", "open"}:
            return "unknown"
    elif encryption in {"none", "open"}:
        return "open"
    if "wpa3" in authentication and "wpa2" in authentication:
        return "wpa2"
    if "wpa3" in authentication:
        return "wpa3"
    if "wpa2" in authentication:
        return "wpa2"
    if "wpa" in authentication:
        return "wpa"
    return "unknown"


def _group_access_points(networks):
    groups = {}
    for index, network in enumerate(networks):
        if not isinstance(network, dict):
            continue

        ssid = network.get("ssid")
        bssid = _normalise_bssid(network.get("bssid"))
        if not isinstance(ssid, str) or not ssid or not bssid:
            continue

        security = _security(network)
        groups.setdefault(ssid, {}).setdefault(bssid, {}).setdefault(security, []).append(
            (index, network)
        )
    return groups


def detect_evil_twins(networks):
    """Return possible evil-twin findings, keyed by scanned network index.

    A duplicate SSID alone is not suspicious: legitimate Wi-Fi systems often
    use several access points with the same name. A finding requires distinct,
    valid BSSIDs advertising known security profiles, with at least one weaker
    profile than another. This is an indicator, not proof of malicious intent.
    """
    findings = {}

    for access_points in _group_access_points(networks).values():
        profiles = {}
        for bssid, observations in access_points.items():
            observed_profiles = [
                profile for profile in observations if profile != "unknown"
            ]
            if len(observations) != 1 or len(observed_profiles) != 1:
                continue
            profile = observed_profiles[0]
            profiles.setdefault(profile, []).extend(observations[profile])

        if len(profiles) < 2:
            continue

        strongest = max(profiles, key=_SECURITY_PRIORITY.__getitem__)
        strongest_priority = _SECURITY_PRIORITY[strongest]
        for profile, observations in profiles.items():
            if _SECURITY_PRIORITY[profile] >= strongest_priority:
                continue

            for index, network in observations:
                findings[index] = {
                    "ssid": network.get("ssid", ""),
                    "bssid": network.get("bssid", ""),
                    "security": profile,
                    "trusted_security": strongest,
                    "reason": (
                        "The same SSID is advertised by another BSSID with "
                        f"stronger security ({strongest} vs {profile})."
                    ),
                }

    return findings


def get_multi_ap_info(networks):
    """Describe duplicate-SSID groups with a consistent security profile."""
    info = {}

    for access_points in _group_access_points(networks).values():
        profiles = {}
        for observations in access_points.values():
            observed_profiles = [
                profile for profile in observations if profile != "unknown"
            ]
            if len(observations) != 1 or len(observed_profiles) != 1:
                continue
            profiles.setdefault(observed_profiles[0], []).extend(
                observations[observed_profiles[0]]
            )

        if len(profiles) != 1:
            continue

        profile, observations = next(iter(profiles.items()))
        access_point_count = sum(
            1
            for observed_profiles in access_points.values()
            if len(observed_profiles) == 1 and profile in observed_profiles
        )
        if access_point_count < 2:
            continue

        for index, network in observations:
            info[index] = {
                "ssid": network.get("ssid", ""),
                "count": access_point_count,
                "security": profile,
            }

    return info
