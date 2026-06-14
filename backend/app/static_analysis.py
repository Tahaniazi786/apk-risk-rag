"""
Static analysis module using androguard.
Extracts permissions, API calls, strings, and manifest data from an APK,
then converts findings into a structured behavior profile + text description
suitable for embedding/RAG retrieval.
"""

import re
from androguard.misc import AnalyzeAPK


# Permission -> behavior tag mapping (used for both scoring hints and RAG query construction)
PERMISSION_BEHAVIOR_MAP = {
    "android.permission.READ_SMS": "sms_otp_access",
    "android.permission.RECEIVE_SMS": "sms_interception",
    "android.permission.SEND_SMS": "sms_worm_propagation",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility_abuse",
    "android.permission.SYSTEM_ALERT_WINDOW": "overlay_attack",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "notification_listener_abuse",
    "android.permission.READ_CONTACTS": "contact_harvesting",
    "android.permission.READ_CALL_LOG": "call_log_exfiltration",
    "android.permission.ACCESS_FINE_LOCATION": "location_tracking",
    "android.permission.CAMERA": "surveillance_capability",
    "android.permission.RECORD_AUDIO": "surveillance_capability",
    "android.permission.REQUEST_INSTALL_PACKAGES": "dropper_behavior",
    "android.permission.BIND_DEVICE_ADMIN": "device_admin_abuse",
    "android.permission.QUERY_ALL_PACKAGES": "app_enumeration",
    "android.permission.READ_PHONE_STATE": "device_fingerprinting",
    "android.permission.CALL_PHONE": "call_initiation",
}

# Suspicious API call signatures to grep for in decompiled strings/methods
SUSPICIOUS_API_PATTERNS = {
    "SmsManager": "sms_interception",
    "getRunningTasks": "app_enumeration",
    "TelephonyManager": "device_fingerprinting",
    "ClipboardManager": "clipboard_hijacking",
    "MediaRecorder": "surveillance_capability",
    "DevicePolicyManager": "device_admin_abuse",
    "AccessibilityService": "accessibility_abuse",
    "TYPE_APPLICATION_OVERLAY": "overlay_attack",
    "addView": "overlay_attack",
}

# Patterns for finding hardcoded URLs / IPs / suspicious domains in strings
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TELEGRAM_PATTERN = re.compile(r"api\.telegram\.org", re.IGNORECASE)


def analyze_apk(apk_path: str) -> dict:
    """
    Run static analysis on the given APK file path.
    Returns a structured dict with permissions, behaviors, network indicators,
    a risk-relevant feature list, and a text profile for embedding.
    """
    a, d, dx = AnalyzeAPK(apk_path)

    package_name = a.get_package()
    app_name = a.get_app_name()
    permissions = a.get_permissions()

    # Map permissions -> behavior tags
    detected_behaviors = set()
    for perm in permissions:
        if perm in PERMISSION_BEHAVIOR_MAP:
            detected_behaviors.add(PERMISSION_BEHAVIOR_MAP[perm])

    # Scan all strings in the APK for suspicious API usage and network indicators
    all_strings = []
    try:
        for s in d.get_strings():
            all_strings.append(str(s))
    except Exception:
        pass

    joined_strings = "\n".join(all_strings)

    for api_pattern, behavior in SUSPICIOUS_API_PATTERNS.items():
        if api_pattern in joined_strings:
            detected_behaviors.add(behavior)

    # Network indicators
    urls = list(set(URL_PATTERN.findall(joined_strings)))[:10]
    ips = list(set(IP_PATTERN.findall(joined_strings)))[:10]
    uses_telegram_c2 = bool(TELEGRAM_PATTERN.search(joined_strings))
    if uses_telegram_c2:
        detected_behaviors.add("encrypted_exfiltration")

    if urls or ips:
        detected_behaviors.add("c2_communication")

    # Check for obfuscation indicators (heuristic: high ratio of short/garbage class names)
    try:
        classes = dx.get_classes()
        class_names = [c.name for c in classes]
        short_names = [c for c in class_names if len(re.sub(r"[^a-zA-Z]", "", c.split("/")[-1])) <= 2]
        obfuscation_ratio = len(short_names) / max(1, len(class_names))
    except Exception:
        obfuscation_ratio = 0.0

    if obfuscation_ratio > 0.3:
        detected_behaviors.add("delayed_activation")  # treat heavy obfuscation as evasion signal

    # Build network description
    network_desc_parts = []
    if uses_telegram_c2:
        network_desc_parts.append("contacts a command-and-control server via Telegram Bot API")
    if urls:
        network_desc_parts.append(f"contains {len(urls)} hardcoded URL(s) ({', '.join(urls[:3])}...)")
    if ips:
        network_desc_parts.append(f"contains {len(ips)} hardcoded IP address(es) ({', '.join(ips[:3])})")
    if not network_desc_parts:
        network_desc_parts.append("no obvious hardcoded C2 indicators found in static strings")

    network_description = "; ".join(network_desc_parts)

    # Build the text profile (used for embedding + RAG query + LLM context)
    profile_text = (
        f"App: {app_name} ({package_name}). "
        f"Permissions: {', '.join(permissions) if permissions else 'none declared'}. "
        f"Behaviors detected via static analysis: {', '.join(sorted(detected_behaviors)) if detected_behaviors else 'none'}. "
        f"Network indicators: {network_description}. "
        f"Obfuscation ratio (heuristic): {obfuscation_ratio:.2f}."
    )

    return {
        "package_name": package_name,
        "app_name": app_name,
        "permissions": permissions,
        "detected_behaviors": sorted(detected_behaviors),
        "network_indicators": {
            "urls": urls,
            "ips": ips,
            "uses_telegram_c2": uses_telegram_c2,
        },
        "obfuscation_ratio": round(obfuscation_ratio, 3),
        "profile_text": profile_text,
    }
