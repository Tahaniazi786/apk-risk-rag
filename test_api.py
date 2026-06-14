#!/usr/bin/env python3
"""
Quick smoke test for the backend API using /analyze-text (no APK file needed).
Usage: python3 test_api.py [--mock] [--base-url http://localhost:8000]
"""

import sys
import json
import argparse
import requests

MALICIOUS_PROFILE = (
    "App requests READ_SMS, RECEIVE_SMS, BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW. "
    "Contacts C2 via Telegram Bot API. Displays overlay screens over banking apps."
)
MALICIOUS_BEHAVIORS = [
    "sms_otp_access", "sms_interception", "accessibility_abuse",
    "overlay_attack", "c2_communication", "encrypted_exfiltration"
]

BENIGN_PROFILE = (
    "App requests INTERNET, CAMERA. Uses SMS Retriever API for OTP autofill. "
    "No accessibility service, no overlay creation, certificate pinning to verified domains."
)
BENIGN_BEHAVIORS = []


def run(base_url, use_mock, profile_text, behaviors, label):
    print(f"\n=== {label} (mock={use_mock}) ===")
    resp = requests.post(
        f"{base_url}/analyze-text",
        params={"use_mock": str(use_mock).lower()},
        json={"profile_text": profile_text, "detected_behaviors": behaviors},
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    v = data["verdict"]
    print("Risk Score:", v["total_risk_score"])
    print("Verdict:", v["verdict_summary"])
    print("Top precedent matches:")
    for m in v.get("similarity_matches", [])[:3]:
        print(f"  - {m['family']} ({m['variant']}): {m['similarity_percent']}%")
    print("Used mock fallback:", data["used_mock_fallback"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--mock", action="store_true")
    args = parser.parse_args()

    # health check
    try:
        h = requests.get(f"{args.base_url}/health", timeout=5)
        print("Health:", h.json())
        stats = requests.get(f"{args.base_url}/db-stats", timeout=5)
        print("DB stats:", stats.json())
    except Exception as e:
        print(f"Could not reach backend at {args.base_url}: {e}")
        sys.exit(1)

    run(args.base_url, args.mock, MALICIOUS_PROFILE, MALICIOUS_BEHAVIORS, "Malicious-like profile")
    run(args.base_url, args.mock, BENIGN_PROFILE, BENIGN_BEHAVIORS, "Benign-like profile")
