"""
Fallback mock verdicts for demo reliability.
If the Groq API call fails (rate limit, network issue, etc.) during a live demo,
this provides a pre-baked but realistic verdict so the demo doesn't break.
"""

MOCK_VERDICT_MALICIOUS = {
    "similarity_matches": [
        {
            "family": "Anubis",
            "variant": "Anubis v1 - Classic OTP Stealer",
            "similarity_percent": 89.0,
            "reasoning": "Both samples request READ_SMS/RECEIVE_SMS combined with BIND_ACCESSIBILITY_SERVICE and SYSTEM_ALERT_WINDOW, and both exhibit C2 communication patterns consistent with dynamic infrastructure."
        },
        {
            "family": "Hydra",
            "variant": "Hydra - Standalone Overlay Variant",
            "similarity_percent": 74.0,
            "reasoning": "Shares accessibility-based overlay attack capability and SMS interception, though this sample lacks the app-enumeration behavior seen in the Hydra variant."
        }
    ],
    "evolution_tree": {
        "closest_family": "Anubis",
        "relation_description": "This APK appears to be a variant of Anubis v1, retaining the core OTP interception and overlay attack capabilities with similar permission requests.",
        "mermaid_diagram": "graph TD\n  A[Anubis] --> B[Anubis v1 - Classic OTP Stealer]\n  A --> C[Anubis v2 - Ransomware Hybrid]\n  B --> D[This APK - 89% similar]"
    },
    "kill_chain": [
        {
            "step": 1,
            "technique_id": "T1056",
            "technique_name": "Input Capture / Keylogging",
            "description": "The app requests BIND_ACCESSIBILITY_SERVICE, granting it the ability to read screen content and capture user input across other applications, including banking apps."
        },
        {
            "step": 2,
            "technique_id": "T1411",
            "technique_name": "Input Prompt / Overlay Attack",
            "description": "Using SYSTEM_ALERT_WINDOW permission, the app can display a fake login screen on top of a legitimate banking app to capture entered credentials."
        },
        {
            "step": 3,
            "technique_id": "T1414",
            "technique_name": "SMS Interception",
            "description": "With READ_SMS and RECEIVE_SMS permissions, the app intercepts incoming OTP messages used for two-factor authentication."
        },
        {
            "step": 4,
            "technique_id": "T1437",
            "technique_name": "C2 Communication",
            "description": "Captured credentials and OTPs are exfiltrated to a remote command-and-control server, consistent with the Telegram Bot API pattern observed in similar Anubis samples."
        }
    ],
    "score_breakdown": {
        "accessibility_abuse": 20,
        "otp_interception": 24,
        "overlay_attack": 16,
        "c2_communication": 17,
        "credential_theft_pattern": 16
    },
    "total_risk_score": 93,
    "counterfactual": "If the BIND_ACCESSIBILITY_SERVICE permission were absent, this app would lose its overlay attack and keylogging capability, and the risk score would likely drop from 93 to approximately 35, reflecting only the residual OTP-interception risk.",
    "threat_actor_attribution": "This sample's behavior profile resembles financially motivated Android banking trojan campaigns historically associated with the Anubis family, which have targeted banking applications across India and Europe since 2023.",
    "predicted_next_actions": [
        {"action": "Credential Theft via Overlay", "probability_percent": 91},
        {"action": "OTP Interception for 2FA Bypass", "probability_percent": 88},
        {"action": "Banking Session Hijack", "probability_percent": 76}
    ],
    "compliance_violations": [
        {
            "regulation": "CERT-In Advisory on Android Banking Trojans (Accessibility Service Abuse)",
            "violation_description": "The app requests BIND_ACCESSIBILITY_SERVICE without any disclosed accessibility-related function, matching the high-risk pattern flagged by CERT-In as the primary enabler of overlay attacks."
        },
        {
            "regulation": "RBI Master Direction on Digital Payment Security Controls",
            "violation_description": "The app requests unrestricted READ_SMS/RECEIVE_SMS permissions for what appears to be OTP-related interception, rather than using the restricted SMS Retriever API mandated for secure mobile banking."
        }
    ],
    "verdict_summary": "CONFIRMED MALICIOUS (high confidence). This application closely matches the Anubis banking trojan family, combining accessibility-service abuse, screen overlay attacks, and OTP interception to steal banking credentials and bypass two-factor authentication. Recommended action: block distribution immediately, alert affected customers, and report to CERT-In."
}

MOCK_VERDICT_BENIGN = {
    "similarity_matches": [
        {
            "family": "Legitimate Banking App",
            "variant": "Official Bank App with SMS Autofill",
            "similarity_percent": 18.0,
            "reasoning": "Low similarity - this app's permission set does not overlap meaningfully with known malware precedent cases. No accessibility service, overlay, or SMS interception behaviors detected."
        }
    ],
    "evolution_tree": {
        "closest_family": "None",
        "relation_description": "No significant precedent match found. This app's behavior profile does not align closely with any known malware family in the knowledge base.",
        "mermaid_diagram": "graph TD\n  A[No Strong Precedent Match] --> B[This APK - low similarity to all known families]"
    },
    "kill_chain": [],
    "score_breakdown": {
        "standard_permissions": 3,
        "no_anomalies_detected": 2
    },
    "total_risk_score": 8,
    "counterfactual": "This app's current permission set and behavior profile do not contain any high-risk indicators, so there is no single permission whose removal would meaningfully change the risk score.",
    "threat_actor_attribution": "No threat actor attribution applicable - this profile does not match known malicious campaign patterns.",
    "predicted_next_actions": [
        {"action": "Normal Application Operation", "probability_percent": 95}
    ],
    "compliance_violations": [],
    "verdict_summary": "LIKELY BENIGN (low confidence concern). This application's permission and behavior profile does not closely match any known malware precedent in the database and shows no high-risk indicators such as accessibility service abuse, overlay attacks, or SMS interception. Recommended action: no immediate intervention required, but periodic re-scanning is advised."
}


def get_mock_verdict(detected_behaviors: list) -> dict:
    """Return an appropriate mock verdict based on whether high-risk behaviors were detected."""
    high_risk_indicators = {
        "accessibility_abuse", "overlay_attack", "sms_interception", "sms_otp_access",
        "notification_listener_abuse", "remote_access_capability", "device_admin_abuse",
    }
    if any(b in high_risk_indicators for b in detected_behaviors):
        return MOCK_VERDICT_MALICIOUS
    return MOCK_VERDICT_BENIGN
