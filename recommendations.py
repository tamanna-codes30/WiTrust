def get_recommendations(level, reasons):

    recommendations = []

    text = " ".join(reasons).lower()


    # HIGH RISK

    if level == "HIGH":

        recommendations.append(
            "Avoid connecting to this network until "
            "its authenticity is verified."
        )

        recommendations.append(
            "Do not enter passwords, banking details, "
            "or other sensitive information on this network."
        )


    # MEDIUM RISK

    elif level == "MEDIUM":

        recommendations.append(
            "Verify the network name with the owner "
            "or service provider before connecting."
        )

        recommendations.append(
            "Avoid sensitive activity if you are unsure "
            "whether the network is genuine."
        )


    # LOW RISK

    else:

        recommendations.append(
            "The network shows no major risk indicators "
            "under the current WiTrust rules."
        )

        recommendations.append(
            "Keep your device and Wi-Fi software updated."
        )


    # OPEN NETWORK

    if "open network" in text or "no encryption" in text:

        recommendations.append(
            "Prefer a password-protected network when possible."
        )

        recommendations.append(
            "If you must use open Wi-Fi, avoid sensitive "
            "activities and prefer HTTPS websites."
        )


    # WEP

    if "wep security" in text:

        recommendations.append(
            "WEP is outdated and should not be used "
            "for modern Wi-Fi security."
        )

        recommendations.append(
            "Prefer a network using WPA2 or WPA3 security."
        )


    # UNKNOWN SECURITY

    if "could not be determined" in text:

        recommendations.append(
            "WiTrust could not verify the network's "
            "security information."
        )

        recommendations.append(
            "Check the network settings or verify "
            "the network with its owner."
        )


    # KEEP DEVICE UPDATED

    if level != "HIGH":

        recommendations.append(
            "Keep your operating system and security "
            "software updated."
        )


    return recommendations