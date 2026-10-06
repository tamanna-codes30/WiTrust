from recommendations import get_recommendations


SUSPICIOUS_WORDS = {
    "free",
    "public",
    "guest",
    "airport",
    "hotel",
    "cafe",
    "coffee",
    "bank",
    "official",
    "admin"
}


def assess_network(network):

    score = 0
    reasons = []

    authentication = (
        network.get("authentication") or ""
    ).lower()

    encryption = (
        network.get("encryption") or ""
    ).lower()

    ssid = (
        network.get("ssid") or ""
    ).lower()


    # Classify security type

    if "wpa3" in authentication:

        security_note = "WPA3 security was detected."
        security_status = "PROTECTED"

    elif "wpa2" in authentication:

        security_note = "WPA2 security was detected."
        security_status = "PROTECTED"

    elif "wpa" in authentication:

        security_note = "WPA-based security was detected."
        security_status = "PROTECTED"

    elif "wep" in authentication or "wep" in encryption:

        security_note = "WEP security was detected."
        security_status = "OUTDATED"

    elif "open" in authentication or encryption in {"none", "open"}:

        security_note = "The network is open."
        security_status = "OPEN"

    else:

        security_note = "Security type could not be classified."
        security_status = "UNKNOWN"


    # Check for open Wi-Fi

    if "open" in authentication or encryption in {"none", "open"}:

        score += 35

        reasons.append(
            "Open network or no encryption was reported."
        )


    # Check for old WEP security

    if "wep" in authentication or "wep" in encryption:

        score += 30

        reasons.append(
            "WEP security was detected."
        )


    # Check for missing security information

    if not authentication and not encryption:

        score += 10

        reasons.append(
            "Security information could not be determined."
        )


    # Check network name

    words = (
        ssid
        .replace("-", " ")
        .replace("_", " ")
        .split()
    )


    found_words = []

    for word in words:

        if word in SUSPICIOUS_WORDS:

            found_words.append(word)


    # Remove duplicate keywords

    found_words = list(
        dict.fromkeys(found_words)
    )


    if found_words:

        score += 10

        keyword_text = ", ".join(
            found_words
        )

        reasons.append(
            f"Network name contains keyword(s): "
            f"{keyword_text}."
        )


    # Keep score between 0 and 100

    score = min(
        score,
        100
    )


    # Decide risk level

    if score >= 60:

        level = "HIGH"

    elif score >= 30:

        level = "MEDIUM"

    else:

        level = "LOW"


    # Put security information first

    reasons.insert(
        0,
        security_note
    )


    return {
        "score": score,
        "level": level,
        "security_status": security_status,
        "reasons": reasons,
        "recommendations": get_recommendations(
            level,
            reasons
        )
    }


# ==================================================
# CONNECTED NETWORK COMPARISON
# ==================================================

def compare_connected_network(
    current_network,
    nearby_networks
):

    current_ssid = (
        current_network.get("ssid") or ""
    )


    current_assessment = assess_network(
        current_network
    )


    total_networks = len(
        nearby_networks
    )


    comparison = []


    # No current network

    if not current_ssid:

        comparison.append(
            "No currently connected Wi-Fi network was detected."
        )

        return {
            "current": current_assessment,
            "total_nearby": total_networks,
            "comparison": comparison
        }


    # Current network information

    comparison.append(
        f"Current network: {current_ssid}"
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


    # Count security categories

    protected_count = 0
    open_count = 0
    outdated_count = 0


    for network in nearby_networks:

        assessment = assess_network(
            network
        )


        if assessment["security_status"] == "PROTECTED":

            protected_count += 1

        elif assessment["security_status"] == "OPEN":

            open_count += 1

        elif assessment["security_status"] == "OUTDATED":

            outdated_count += 1


    comparison.append(
        f"Protected networks nearby: "
        f"{protected_count}"
    )


    comparison.append(
        f"Open networks nearby: "
        f"{open_count}"
    )


    comparison.append(
        f"Outdated networks nearby: "
        f"{outdated_count}"
    )


    # Evaluate current network

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


    # Compare current risk with nearby networks

    nearby_scores = []


    for network in nearby_networks:

        if network.get("ssid") == current_ssid:

            continue


        assessment = assess_network(
            network
        )


        nearby_scores.append(
            assessment["score"]
        )


    if nearby_scores:

        average_score = (
            sum(nearby_scores)
            / len(nearby_scores)
        )


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