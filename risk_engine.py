from collections import Counter

from recommendations import get_recommendations


SUSPICIOUS_WORDS = {
    "free", "public", "guest", "airport", "hotel", "cafe", "coffee",
    "bank", "official", "admin",
}
RISK_LEVELS = ((60, "HIGH"), (30, "MEDIUM"), (0, "LOW"))


def _text(value):
    return str(value).strip().casefold() if value is not None else ""


def _security_status(authentication, encryption):
    if "wep" in authentication or "wep" in encryption:
        return "OUTDATED"
    if any(protocol in authentication for protocol in ("wpa3", "wpa2", "wpa")):
        if encryption in {"none", "open"}:
            return "UNKNOWN"
        return "PROTECTED"
    if "owe" in authentication:
        return "PROTECTED"
    if authentication in {"open", "open system", "none"}:
        return "OPEN"
    if encryption in {"none", "open"}:
        return "OPEN"
    return "UNKNOWN"


def _valid_bssid(value):
    parts = _text(value).replace("-", ":").split(":")
    if len(parts) != 6 or any(
        len(part) != 2 or any(char not in "0123456789abcdef" for char in part)
        for part in parts
    ):
        return False
    octets = [int(part, 16) for part in parts]
    return any(octets) and any(octet != 255 for octet in octets) and not octets[0] & 1


def _data_quality(network, security_status, encryption):
    ssid = _text(network.get("ssid"))
    has_valid_bssid = _valid_bssid(network.get("bssid"))
    has_known_security = security_status != "UNKNOWN"
    if not has_valid_bssid or not has_known_security:
        quality = "LOW"
    elif ssid and encryption:
        quality = "HIGH"
    else:
        quality = "MEDIUM"
    limitations = []
    if not ssid:
        limitations.append("SSID is unavailable or redacted.")
    if not has_valid_bssid:
        limitations.append("A valid BSSID was not available.")
    if security_status == "UNKNOWN":
        limitations.append("Security could not be classified from scan data.")
    return quality, limitations


def _data_coverage_score(network, security_status):
    fields = (
        (bool(_text(network.get("ssid"))), 15),
        (_valid_bssid(network.get("bssid")), 25),
        (bool(_text(network.get("authentication"))), 25),
        (bool(_text(network.get("encryption"))), 15),
        (bool(_text(network.get("signal"))), 10),
        (bool(_text(network.get("channel")) and _text(network.get("band"))), 10),
    )
    score = sum(points for present, points in fields if present)
    if security_status == "UNKNOWN":
        score = max(0, score - 15)
    return score


def assess_network(network, context=None):
    """Score observable Wi-Fi risks, with optional reputation/detector evidence.

    ``context`` may contain an ``evil_twin_finding`` dictionary and/or a
    ``reputation`` record whose status is ``malicious`` or ``trusted``. A
    trusted label never cancels concrete security weaknesses.
    """
    if not isinstance(network, dict):
        raise ValueError("A network must be provided as a dictionary.")
    if context is not None and not isinstance(context, dict):
        raise ValueError("Assessment context must be a dictionary.")

    context = context or {}
    authentication = _text(network.get("authentication"))
    encryption = _text(network.get("encryption"))
    ssid = _text(network.get("ssid"))
    security_status = _security_status(authentication, encryption)
    score = 0
    reasons = []
    signals = []
    observations = []

    if security_status == "OPEN":
        score += 35
        reasons.append("Open network or no encryption was reported.")
        signals.append({"code": "open_wifi", "points": 35})
    elif security_status == "OUTDATED":
        if "wep" in authentication or "wep" in encryption:
            score += 60
            reasons.append("WEP security was detected.")
            signals.append({"code": "wep", "points": 60})
        else:
            score += 30
            reasons.append("Legacy WPA security was detected.")
            signals.append({"code": "legacy_wpa", "points": 30})
    elif security_status == "UNKNOWN":
        if any(protocol in authentication for protocol in ("wpa2", "wpa3", "wpa")):
            score += 20
            reasons.append("Authentication and encryption reports conflict.")
            signals.append({"code": "conflicting_security_metadata", "points": 20})
        else:
            score += 10
            reasons.append("Security information could not be determined.")
            signals.append({"code": "unknown_security", "points": 10})
    elif "wpa" in authentication and "wpa2" not in authentication and "wpa3" not in authentication:
        score += 30
        security_status = "OUTDATED"
        reasons.append("Legacy WPA security was detected.")
        signals.append({"code": "legacy_wpa", "points": 30})

    if "tkip" in encryption:
        score += 30
        security_status = "OUTDATED"
        reasons.append("The legacy TKIP cipher was reported.")
        signals.append({"code": "legacy_tkip", "points": 30})

    finding = context.get("evil_twin_finding")
    if finding is not None:
        if not isinstance(finding, dict):
            raise ValueError("An evil-twin finding must be provided as a dictionary.")
        if not _text(finding.get("reason")):
            raise ValueError("An evil-twin finding must include a reason.")
        score += 45
        reasons.append(
            "Possible evil-twin indicator: "
            + _text(finding.get("reason") or "same SSID has a weaker security profile.")
        )
        signals.append({"code": "evil_twin_indicator", "points": 45})

    reputation = context.get("reputation")
    if reputation is not None:
        if not isinstance(reputation, dict):
            raise ValueError("A reputation record must be provided as a dictionary.")
        reputation_status = _text(reputation.get("status"))
        if reputation_status == "malicious":
            score += 60
            source = _text(reputation.get("source")) or "local reputation data"
            reasons.append(f"BSSID is listed as malicious by {source}.")
            signals.append({"code": "malicious_bssid", "points": 60})
        elif reputation_status == "trusted":
            observations.append(
                "BSSID is locally marked trusted; this does not override weak security signals."
            )

    keywords = sorted(set(ssid.replace("-", " ").replace("_", " ").split()) & SUSPICIOUS_WORDS)
    if keywords:
        observations.append(
            "SSID contains generic keyword(s) " + ", ".join(keywords)
            + "; name alone is not treated as evidence of malicious activity."
        )

    score = min(score, 100)
    level = next(level for minimum, level in RISK_LEVELS if score >= minimum)
    data_quality, limitations = _data_quality(network, security_status, encryption)
    data_coverage_score = _data_coverage_score(network, security_status)
    security_note = {
        "OPEN": "The network is open.",
        "OUTDATED": "Outdated Wi-Fi security or cipher was detected.",
        "PROTECTED": "WPA/OWE security was detected; this does not verify network identity.",
        "UNKNOWN": "Security type could not be classified.",
    }[security_status]

    return {
        "score": score,
        "level": level,
        "security_status": security_status,
        "data_quality": data_quality,
        "data_coverage_score": data_coverage_score,
        "limitations": limitations,
        "signals": signals,
        "observations": observations,
        "reasons": [security_note, *reasons],
        "recommendations": get_recommendations(level, [security_note, *reasons]),
    }


# ==================================================
# CONNECTED NETWORK COMPARISON
# ==================================================

def compare_connected_network(
    current_network,
    nearby_networks,
    current_context=None,
    nearby_contexts=None,
):

    if not isinstance(current_network, dict):
        raise ValueError("The current network must be provided as a dictionary.")
    if not isinstance(nearby_networks, (list, tuple)):
        raise ValueError("Nearby networks must be provided as a list.")
    if nearby_contexts is not None and (
        not isinstance(nearby_contexts, (list, tuple))
        or len(nearby_contexts) != len(nearby_networks)
    ):
        raise ValueError("Each nearby network must have a matching assessment context.")

    current_ssid = (
        current_network.get("ssid") or ""
    )
    current_bssid = str(current_network.get("bssid") or "").casefold().replace("-", ":")
    is_connected = bool(current_network.get("connected", bool(current_ssid)))
    current_assessment = assess_network(
        current_network,
        context=current_context,
    )
    total_networks = len(
        nearby_networks
    )
    comparison = []

    if not is_connected:

        comparison.append(
            "No currently connected Wi-Fi network was detected."
        )

        return {
            "current": current_assessment,
            "total_nearby": total_networks,
            "comparison": comparison
        }

    if current_ssid:
        current_name = current_ssid
    elif current_network.get("ssid_redacted"):
        current_name = "<SSID hidden by macOS Location Services>"
    else:
        current_name = "<SSID unavailable>"
    comparison.append(
        f"Current network: {current_name}"
    )
    if current_network.get("ssid_redacted"):
        comparison.append(
            "macOS is withholding the network name; allow Location Services to identify it."
        )
    comparison.append(
        f"Security: "
        f"{current_network.get('authentication') or 'Unknown'}"
    )


    comparison.append(
        f"Encryption: "
        f"{current_network.get('encryption') or 'Unknown'}"
    )


    comparison.append(
        f"Risk: "
        f"{current_assessment['score']}/100 - "
        f"{current_assessment['level']}"
    )


    comparison.append(
        f"Nearby networks detected: "
        f"{total_networks}"
    )


    if nearby_contexts is None:
        nearby_contexts = [None] * len(nearby_networks)
    nearby_assessments = [
        assess_network(network, context=context)
        for network, context in zip(nearby_networks, nearby_contexts)
    ]
    status_counts = Counter(
        assessment["security_status"] for assessment in nearby_assessments
    )
    comparison.append(
        f"Protected networks nearby: {status_counts['PROTECTED']}"
    )
    comparison.append(
        f"Open networks nearby: {status_counts['OPEN']}"
    )
    comparison.append(
        f"Outdated networks nearby: {status_counts['OUTDATED']}"
    )

    if current_assessment["security_status"] == "PROTECTED":

        comparison.append(
            "✓ Your current network uses protected Wi-Fi security."
        )

    elif current_assessment["security_status"] == "OPEN":

        comparison.append(
            "⚠ Your current network is open and "
            "does not report encryption."
        )

    elif current_assessment["security_status"] == "OUTDATED":

        comparison.append(
            "⚠ Your current network uses outdated "
            "Wi-Fi security."
        )

    else:

        comparison.append(
            "⚠ WiTrust could not confirm the security "
            "type of your current network."
        )


    nearby_scores = [
        assessment["score"]
        for network, assessment in zip(nearby_networks, nearby_assessments)
        if not (
            (current_ssid and network.get("ssid") == current_ssid)
            or (
                current_bssid
                and str(network.get("bssid") or "").casefold().replace("-", ":")
                == current_bssid
            )
        )
    ]

    if not current_ssid and not current_bssid:
        comparison.append(
            "Nearby risk comparison is unavailable until macOS reveals the current network identity."
        )
    elif nearby_scores:
        average_score = sum(nearby_scores) / len(nearby_scores)
        if current_assessment["score"] < average_score:

            comparison.append(
                "✓ Your current network has a lower "
                "risk score than the average nearby network."
            )

        elif current_assessment["score"] > average_score:

            comparison.append(
                "⚠ Your current network has a higher "
                "risk score than the average nearby network."
            )

        else:

            comparison.append(
                "• Your current network has a risk score "
                "close to the nearby-network average."
            )


    return {
        "current": current_assessment,
        "total_nearby": total_networks,
        "comparison": comparison
    }
