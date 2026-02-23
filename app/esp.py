def detect_esp_from_mx(mxs: list[str]) -> str:
    if not mxs:
        return "unknown"
    mx = mxs[0].lower()

    # Common ESP patterns
    if "google" in mx or "gmail-smtp-in" in mx or "googlemail" in mx:
        return "google"
    if "outlook" in mx or "protection.outlook" in mx:
        return "microsoft"
    if "zoho" in mx:
        return "zoho"

    # Gateways
    if "mimecast" in mx:
        return "mimecast"
    if "proofpoint" in mx or "pphosted" in mx:
        return "proofpoint"
    if "barracuda" in mx:
        return "barracuda"

    return "unknown"
