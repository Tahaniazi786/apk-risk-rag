"""
Seed data for the Precedent-Based Verdict Engine.
Each case represents a behavior profile of a known malware family variant
(or a benign app for contrast), used to populate ChromaDB for RAG retrieval.
"""

SEED_CASES = [
    # ---------------- ANUBIS FAMILY ----------------
    {
        "id": "anubis_001",
        "family": "Anubis",
        "variant": "Anubis v1 - Classic OTP Stealer",
        "profile_text": (
            "Permissions: READ_SMS, RECEIVE_SMS, BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, "
            "REQUEST_INSTALL_PACKAGES. Behaviors: OTP interception, screen overlay attack on banking apps, "
            "accessibility service abuse to read screen content, credential harvesting via fake login overlays. "
            "Network: contacts dynamic command-and-control server via Telegram Bot API, domain registered "
            "within last 30 days. Threat actor context: financially motivated Android banking trojan, "
            "widespread in campaigns targeting Indian and European banking apps since 2023."
        ),
        "risk_score": 94,
        "score_breakdown": {
            "accessibility_abuse": 20,
            "otp_interception": 25,
            "overlay_attack": 15,
            "credential_theft_pattern": 18,
            "data_exfiltration": 16
        },
        "known_followup_actions": [
            {"action": "Credential Theft", "probability_percent": 92},
            {"action": "Banking Session Hijack", "probability_percent": 81},
            {"action": "Remote Command Execution", "probability_percent": 67}
        ]
    },
    {
        "id": "anubis_002",
        "family": "Anubis",
        "variant": "Anubis v2 - Ransomware Hybrid",
        "profile_text": (
            "Permissions: READ_SMS, RECEIVE_SMS, BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, "
            "WRITE_EXTERNAL_STORAGE, CAMERA, RECORD_AUDIO. Behaviors: OTP interception, screen overlay attack, "
            "file encryption of device storage (ransomware module), microphone and camera access for "
            "surveillance, keylogging via accessibility service. Network: contacts C2 over Telegram Bot API "
            "and a secondary Tor-based fallback domain. Threat actor context: evolved Anubis variant combining "
            "banking trojan capabilities with ransomware, observed in late-2024 campaigns."
        ),
        "risk_score": 97,
        "score_breakdown": {
            "accessibility_abuse": 18,
            "otp_interception": 22,
            "overlay_attack": 14,
            "surveillance_capability": 20,
            "ransomware_module": 23
        },
        "known_followup_actions": [
            {"action": "Credential Theft", "probability_percent": 90},
            {"action": "Device Lockout / Ransom Demand", "probability_percent": 85},
            {"action": "Surveillance Data Exfiltration", "probability_percent": 73}
        ]
    },
    {
        "id": "anubis_003",
        "family": "Anubis",
        "variant": "Anubis Lite - Minimal Footprint",
        "profile_text": (
            "Permissions: READ_SMS, BIND_ACCESSIBILITY_SERVICE, INTERNET. Behaviors: OTP interception only, "
            "no overlay attack module detected, minimal accessibility service usage limited to SMS reading. "
            "Network: single hardcoded IP address for C2, no domain-based communication. Threat actor context: "
            "stripped-down Anubis variant likely used for rapid disposable campaigns or as a dropper-stage payload."
        ),
        "risk_score": 76,
        "score_breakdown": {
            "accessibility_abuse": 12,
            "otp_interception": 25,
            "minimal_overlay": 5,
            "hardcoded_c2": 18,
            "dropper_pattern": 16
        },
        "known_followup_actions": [
            {"action": "OTP Theft", "probability_percent": 88},
            {"action": "Secondary Payload Download", "probability_percent": 70},
            {"action": "Credential Theft", "probability_percent": 55}
        ]
    },

    # ---------------- HYDRA FAMILY ----------------
    {
        "id": "hydra_001",
        "family": "Hydra",
        "variant": "Hydra - Banking Dropper",
        "profile_text": (
            "Permissions: BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, REQUEST_INSTALL_PACKAGES, "
            "READ_PHONE_STATE, INTERNET. Behaviors: acts as a dropper that downloads a secondary malicious "
            "payload post-install, screen overlay attacks targeting European banking apps, accessibility "
            "service used to grant itself additional permissions automatically. Network: contacts a staging "
            "server to fetch the second-stage APK, uses HTTPS with self-signed certificate. Threat actor "
            "context: Hydra dropper family, frequently distributed via fake Flash Player or system update apps."
        ),
        "risk_score": 89,
        "score_breakdown": {
            "accessibility_abuse": 22,
            "dropper_behavior": 24,
            "overlay_attack": 15,
            "self_signed_cert": 12,
            "permission_escalation": 16
        },
        "known_followup_actions": [
            {"action": "Second-Stage Payload Install", "probability_percent": 91},
            {"action": "Banking Session Hijack", "probability_percent": 78},
            {"action": "Permission Escalation", "probability_percent": 84}
        ]
    },
    {
        "id": "hydra_002",
        "family": "Hydra",
        "variant": "Hydra - Standalone Overlay Variant",
        "profile_text": (
            "Permissions: BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, READ_SMS, RECEIVE_SMS, INTERNET, "
            "QUERY_ALL_PACKAGES. Behaviors: enumerates all installed apps to detect target banking apps, "
            "deploys fake login overlays matching detected bank's UI, intercepts SMS-based 2FA codes. Network: "
            "contacts C2 over HTTPS to fetch target-bank-specific overlay templates dynamically. Threat actor "
            "context: standalone Hydra variant without dropper stage, targets a curated list of banking apps "
            "by package name."
        ),
        "risk_score": 91,
        "score_breakdown": {
            "accessibility_abuse": 20,
            "app_enumeration": 14,
            "dynamic_overlay_fetch": 22,
            "sms_interception": 22,
            "targeted_attack_pattern": 13
        },
        "known_followup_actions": [
            {"action": "Credential Theft", "probability_percent": 93},
            {"action": "OTP Interception", "probability_percent": 89},
            {"action": "Banking Session Hijack", "probability_percent": 80}
        ]
    },

    # ---------------- SOVA FAMILY ----------------
    {
        "id": "sova_001",
        "family": "SOVA",
        "variant": "SOVA v4 - Session Cookie Stealer",
        "profile_text": (
            "Permissions: BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, INTERNET, READ_SMS, "
            "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS. Behaviors: steals session cookies from browser and banking "
            "app storage via accessibility service, keylogging across all apps, screen recording capability "
            "for capturing 2FA app codes, overlay attacks. Network: contacts C2 over a custom binary protocol "
            "on a non-standard port, exfiltrates cookies and keystrokes in encrypted batches. Threat actor "
            "context: SOVA banking trojan, known for targeting cryptocurrency wallets and banking apps "
            "simultaneously, active since 2021 with continuous feature additions."
        ),
        "risk_score": 95,
        "score_breakdown": {
            "accessibility_abuse": 19,
            "session_cookie_theft": 24,
            "keylogging": 18,
            "screen_recording": 20,
            "encrypted_exfiltration": 14
        },
        "known_followup_actions": [
            {"action": "Session Hijack via Cookie Theft", "probability_percent": 94},
            {"action": "Crypto Wallet Drain", "probability_percent": 71},
            {"action": "2FA Bypass via Screen Recording", "probability_percent": 86}
        ]
    },
    {
        "id": "sova_002",
        "family": "SOVA",
        "variant": "SOVA - Crypto-Focused Variant",
        "profile_text": (
            "Permissions: BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, INTERNET, QUERY_ALL_PACKAGES. "
            "Behaviors: specifically targets cryptocurrency wallet apps with overlay attacks, clipboard "
            "monitoring to swap copied wallet addresses with attacker-controlled addresses, no SMS/OTP "
            "interception detected. Network: contacts C2 via HTTPS, fetches updated list of targeted wallet "
            "app package names periodically. Threat actor context: SOVA variant repurposed for crypto theft, "
            "clipboard-hijacking is a hallmark technique."
        ),
        "risk_score": 84,
        "score_breakdown": {
            "accessibility_abuse": 16,
            "clipboard_hijacking": 26,
            "overlay_attack": 15,
            "app_enumeration": 12,
            "c2_communication": 15
        },
        "known_followup_actions": [
            {"action": "Crypto Wallet Address Swap", "probability_percent": 90},
            {"action": "Credential Theft via Overlay", "probability_percent": 65},
            {"action": "Targeted App List Update", "probability_percent": 77}
        ]
    },

    # ---------------- TEABOT FAMILY ----------------
    {
        "id": "teabot_001",
        "family": "TeaBot",
        "variant": "TeaBot - Remote Access Trojan Mode",
        "profile_text": (
            "Permissions: BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, INTERNET, READ_SMS, RECEIVE_SMS, "
            "FOREGROUND_SERVICE. Behaviors: provides full remote screen control to attacker (VNC-like remote "
            "access via accessibility service), live screen streaming to C2, overlay attacks on banking apps, "
            "OTP interception. Network: maintains persistent WebSocket connection to C2 for real-time remote "
            "control. Threat actor context: TeaBot (also known as Anatsa), distributed via fake QR code "
            "scanner and PDF reader apps on third-party app stores, capable of full account takeover via "
            "live remote control."
        ),
        "risk_score": 96,
        "score_breakdown": {
            "accessibility_abuse": 20,
            "remote_access_capability": 25,
            "live_screen_streaming": 18,
            "overlay_attack": 14,
            "otp_interception": 19
        },
        "known_followup_actions": [
            {"action": "Full Account Takeover via Remote Control", "probability_percent": 95},
            {"action": "Live Fraudulent Transaction", "probability_percent": 88},
            {"action": "OTP Interception for 2FA Bypass", "probability_percent": 90}
        ]
    },
    {
        "id": "teabot_002",
        "family": "TeaBot",
        "variant": "TeaBot - Dropper Stage",
        "profile_text": (
            "Permissions: INTERNET, REQUEST_INSTALL_PACKAGES, READ_PHONE_STATE. Behaviors: minimal initial "
            "footprint, masquerades as a legitimate utility app (QR scanner/PDF reader), downloads the full "
            "TeaBot payload after a delay to evade automated scanning, checks device locale before activating. "
            "Network: contacts a benign-looking CDN URL initially, switches to C2 domain after payload "
            "download. Threat actor context: TeaBot dropper stage, designed specifically to pass app store "
            "automated review by delaying malicious activity."
        ),
        "risk_score": 68,
        "score_breakdown": {
            "delayed_activation": 18,
            "dropper_behavior": 22,
            "locale_check_evasion": 14,
            "cdn_masquerading": 8,
            "minimal_permissions": 6
        },
        "known_followup_actions": [
            {"action": "Full Payload Download Post-Delay", "probability_percent": 87},
            {"action": "Accessibility Permission Request", "probability_percent": 80},
            {"action": "Remote Access Trojan Activation", "probability_percent": 75}
        ]
    },

    # ---------------- EVENTBOT FAMILY ----------------
    {
        "id": "eventbot_001",
        "family": "EventBot",
        "variant": "EventBot - Notification Sniffer",
        "profile_text": (
            "Permissions: BIND_NOTIFICATION_LISTENER_SERVICE, BIND_ACCESSIBILITY_SERVICE, READ_SMS, INTERNET, "
            "SYSTEM_ALERT_WINDOW. Behaviors: reads all device notifications including banking app push "
            "notifications and 2FA codes, overlay attacks, SMS interception as fallback. Network: exfiltrates "
            "notification content to C2 over HTTPS in real time. Threat actor context: EventBot, abuses "
            "Android's notification listener API (originally for accessibility purposes) to intercept "
            "push-notification-based 2FA, targets financial apps across Europe and Asia."
        ),
        "risk_score": 90,
        "score_breakdown": {
            "notification_listener_abuse": 24,
            "accessibility_abuse": 17,
            "otp_interception": 20,
            "overlay_attack": 14,
            "realtime_exfiltration": 15
        },
        "known_followup_actions": [
            {"action": "Push Notification 2FA Bypass", "probability_percent": 92},
            {"action": "Credential Theft via Overlay", "probability_percent": 79},
            {"action": "Banking Session Hijack", "probability_percent": 74}
        ]
    },

    # ---------------- FLUBOT FAMILY ----------------
    {
        "id": "flubot_001",
        "family": "FluBot",
        "variant": "FluBot - SMS Worm Variant",
        "profile_text": (
            "Permissions: READ_SMS, SEND_SMS, RECEIVE_SMS, READ_CONTACTS, BIND_ACCESSIBILITY_SERVICE, "
            "SYSTEM_ALERT_WINDOW. Behaviors: self-propagates by sending SMS with malicious download links to "
            "all contacts in the device's address book (worm behavior), overlay attacks on banking and crypto "
            "apps, OTP interception. Network: each infected device acts as a distribution node, C2 domains "
            "rotate frequently using domain generation algorithm (DGA). Threat actor context: FluBot, "
            "notable for rapid self-propagation via SMS, caused large-scale infection waves across Europe "
            "in 2021-2022 before takedown."
        ),
        "risk_score": 93,
        "score_breakdown": {
            "sms_worm_propagation": 26,
            "accessibility_abuse": 18,
            "contact_harvesting": 14,
            "overlay_attack": 15,
            "dga_c2_communication": 20
        },
        "known_followup_actions": [
            {"action": "Mass SMS Self-Propagation", "probability_percent": 96},
            {"action": "Credential Theft via Overlay", "probability_percent": 80},
            {"action": "Contact List Exfiltration", "probability_percent": 85}
        ]
    },

    # ---------------- CERBERUS FAMILY ----------------
    {
        "id": "cerberus_001",
        "family": "Cerberus",
        "variant": "Cerberus - RAT with Keylogger",
        "profile_text": (
            "Permissions: BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, READ_SMS, RECEIVE_SMS, "
            "PACKAGE_USAGE_STATS, INTERNET. Behaviors: full keylogging across all applications, overlay "
            "attacks with bank-specific templates downloaded from C2, device admin privilege abuse to prevent "
            "uninstallation, OTP interception. Network: C2 communication over HTTP with custom encoding to "
            "evade network-based detection. Threat actor context: Cerberus, sold as Malware-as-a-Service "
            "(MaaS) on underground forums, highly configurable by buyers for different target regions."
        ),
        "risk_score": 92,
        "score_breakdown": {
            "accessibility_abuse": 19,
            "keylogging": 18,
            "overlay_attack": 16,
            "device_admin_abuse": 20,
            "otp_interception": 19
        },
        "known_followup_actions": [
            {"action": "Uninstall Prevention via Device Admin", "probability_percent": 89},
            {"action": "Credential Theft via Overlay", "probability_percent": 91},
            {"action": "OTP Interception", "probability_percent": 86}
        ]
    },

    # ---------------- BANKBOT FAMILY ----------------
    {
        "id": "bankbot_001",
        "family": "BankBot",
        "variant": "BankBot - Legacy Overlay Trojan",
        "profile_text": (
            "Permissions: READ_SMS, RECEIVE_SMS, SYSTEM_ALERT_WINDOW, INTERNET, CALL_PHONE. Behaviors: overlay "
            "attacks on a hardcoded list of banking apps, SMS interception, can initiate phone calls "
            "(potential for vishing follow-up). Network: contacts a static C2 IP, no domain rotation, "
            "relatively unsophisticated infrastructure. Threat actor context: BankBot, one of the earlier "
            "Android banking trojan families, less actively maintained but template for many derivative "
            "families."
        ),
        "risk_score": 79,
        "score_breakdown": {
            "overlay_attack": 22,
            "otp_interception": 22,
            "static_c2": 15,
            "call_initiation": 12,
            "hardcoded_targets": 8
        },
        "known_followup_actions": [
            {"action": "Credential Theft via Overlay", "probability_percent": 83},
            {"action": "OTP Interception", "probability_percent": 81},
            {"action": "Follow-up Vishing Call", "probability_percent": 45}
        ]
    },

    # ---------------- GENERIC SPYWARE ----------------
    {
        "id": "spyware_001",
        "family": "Generic Spyware",
        "variant": "Commercial Stalkerware",
        "profile_text": (
            "Permissions: READ_SMS, READ_CALL_LOG, ACCESS_FINE_LOCATION, CAMERA, RECORD_AUDIO, READ_CONTACTS, "
            "INTERNET. Behaviors: continuous location tracking, call log and SMS exfiltration, hidden app "
            "icon after install, no overlay or accessibility abuse (not a banking trojan). Network: uploads "
            "collected data to a remote dashboard accessible by whoever installed the app. Threat actor "
            "context: commercial stalkerware/spyware, typically used for surveillance rather than direct "
            "financial fraud, but indicates privacy compromise and potential precursor to targeted fraud."
        ),
        "risk_score": 71,
        "score_breakdown": {
            "location_tracking": 15,
            "communication_exfiltration": 20,
            "hidden_app_icon": 16,
            "surveillance_capability": 20
        },
        "known_followup_actions": [
            {"action": "Continuous Surveillance Data Upload", "probability_percent": 95},
            {"action": "Personal Data Sale/Misuse", "probability_percent": 60},
            {"action": "Targeted Social Engineering Setup", "probability_percent": 50}
        ]
    },

    # ---------------- FAKE BANKING APP CLONES ----------------
    {
        "id": "fakeapp_001",
        "family": "Fake Banking App",
        "variant": "Phishing Clone - Direct Credential Capture",
        "profile_text": (
            "Permissions: INTERNET, READ_SMS (requested but used minimally). Behaviors: entire app is a "
            "pixel-perfect clone of a legitimate bank's login screen, captures entered username/password "
            "directly and submits to attacker server, no further malicious behavior post-capture, often "
            "redirects to real bank app/website after capture to avoid suspicion. Network: submits captured "
            "credentials via simple HTTPS POST to attacker-controlled endpoint immediately. Threat actor "
            "context: low-sophistication phishing clone, typically distributed via SMS phishing (smishing) "
            "links rather than app stores."
        ),
        "risk_score": 82,
        "score_breakdown": {
            "ui_clone_phishing": 28,
            "direct_credential_capture": 26,
            "immediate_exfiltration": 18,
            "redirect_evasion": 10
        },
        "known_followup_actions": [
            {"action": "Immediate Credential Exfiltration", "probability_percent": 97},
            {"action": "Account Login Using Stolen Credentials", "probability_percent": 85},
            {"action": "Smishing Campaign Continuation", "probability_percent": 70}
        ]
    },

    # ---------------- LOAN SCAM APPS ----------------
    {
        "id": "loanscam_001",
        "family": "Predatory Loan App",
        "variant": "Instant Loan Data Harvester",
        "profile_text": (
            "Permissions: READ_CONTACTS, READ_CALL_LOG, READ_SMS, CAMERA, ACCESS_FINE_LOCATION, "
            "READ_EXTERNAL_STORAGE. Behaviors: harvests entire contact list and call log immediately on "
            "install under guise of 'eligibility verification', reads SMS for bank statement OTPs to verify "
            "account balance, used later for harassment-based debt collection by contacting victim's contacts. "
            "Network: uploads contact/call log data to remote server before any loan is actually disbursed. "
            "Threat actor context: predatory instant-loan app pattern common on third-party Android app "
            "stores, data harvesting itself is the primary fraud vector, often paired with extortion."
        ),
        "risk_score": 85,
        "score_breakdown": {
            "contact_harvesting": 24,
            "call_log_exfiltration": 18,
            "sms_otp_access": 18,
            "premature_data_collection": 15,
            "extortion_precursor": 10
        },
        "known_followup_actions": [
            {"action": "Contact List Exfiltration Before Service Delivery", "probability_percent": 94},
            {"action": "Harassment-Based Debt Collection", "probability_percent": 78},
            {"action": "Account Balance Verification via SMS", "probability_percent": 65}
        ]
    },

    # ---------------- BENIGN APPS (for counterfactual contrast) ----------------
    {
        "id": "benign_001",
        "family": "Legitimate Banking App",
        "variant": "Official Bank App with SMS Autofill",
        "profile_text": (
            "Permissions: READ_SMS (scoped via SMS Retriever API), INTERNET, CAMERA (for check deposit), "
            "ACCESS_FINE_LOCATION (for ATM locator). Behaviors: uses Android SMS Retriever API for OTP "
            "autofill which does not require broad READ_SMS access, no accessibility service usage, no "
            "overlay creation, all network communication to verified bank domains with certificate pinning. "
            "Threat actor context: none - this is a legitimate, code-signed banking application from a "
            "verified publisher with no anomalous behaviors detected."
        ),
        "risk_score": 8,
        "score_breakdown": {
            "scoped_sms_access": 2,
            "standard_permissions": 1,
            "verified_publisher": 0,
            "certificate_pinning": 0,
            "no_anomalies": 5
        },
        "known_followup_actions": [
            {"action": "Normal Banking Operations", "probability_percent": 99},
            {"action": "OTP Autofill via Retriever API", "probability_percent": 95}
        ]
    },
    {
        "id": "benign_002",
        "family": "Legitimate Utility App",
        "variant": "QR Code Scanner - Verified Publisher",
        "profile_text": (
            "Permissions: CAMERA, INTERNET. Behaviors: scans QR codes and opens resulting URLs in default "
            "browser, no accessibility service, no SMS access, no overlay creation, no background services "
            "beyond camera usage during active scanning. Network: only contacts a crash-reporting analytics "
            "endpoint (standard SDK). Threat actor context: none - legitimate utility app, common app type "
            "that is frequently impersonated by droppers like TeaBot, useful as a contrast baseline."
        ),
        "risk_score": 5,
        "score_breakdown": {
            "minimal_permissions": 1,
            "standard_analytics_sdk": 1,
            "no_anomalies": 3
        },
        "known_followup_actions": [
            {"action": "Normal QR Scanning Operation", "probability_percent": 99}
        ]
    },
    {
        "id": "benign_003",
        "family": "Legitimate Messaging App",
        "variant": "Standard Chat App with Notification Access",
        "profile_text": (
            "Permissions: INTERNET, READ_CONTACTS (for friend discovery, with user consent dialog), CAMERA, "
            "RECORD_AUDIO, BIND_NOTIFICATION_LISTENER_SERVICE (for notification badge counts only). "
            "Behaviors: notification listener used only to count unread messages for badge display, no "
            "content of notifications is read or transmitted, contact access gated behind explicit user "
            "consent screen, end-to-end encrypted communication. Threat actor context: none - legitimate "
            "messaging application, notification listener usage is benign and scoped, useful contrast for "
            "EventBot-style notification abuse."
        ),
        "risk_score": 10,
        "score_breakdown": {
            "scoped_notification_access": 3,
            "consent_gated_contacts": 2,
            "encrypted_communication": 0,
            "no_anomalies": 5
        },
        "known_followup_actions": [
            {"action": "Normal Messaging Operations", "probability_percent": 99}
        ]
    },

    # ---------------- MULE-RELATED / SOCIAL ENGINEERING APPS ----------------
    {
        "id": "muleapp_001",
        "family": "Fake Investment/Trading App",
        "variant": "Pig Butchering Scam App",
        "profile_text": (
            "Permissions: INTERNET, READ_PHONE_STATE, ACCESS_FINE_LOCATION, READ_SMS. Behaviors: displays "
            "fake investment portfolio with manipulated growth figures to encourage larger deposits, "
            "withdrawal requests are blocked or indefinitely delayed via fake 'verification' steps, app "
            "communicates with victim via in-app chat that connects to human social-engineering operators. "
            "Network: all 'transaction' data is client-side only and not reflected in any real financial "
            "system, backend simply logs victim deposit confirmations. Threat actor context: 'pig butchering' "
            "investment scam pattern, often used to recruit victims as unwitting mule account holders for "
            "laundering deposited funds."
        ),
        "risk_score": 88,
        "score_breakdown": {
            "fake_financial_data": 24,
            "withdrawal_blocking": 22,
            "social_engineering_integration": 20,
            "mule_recruitment_pattern": 22
        },
        "known_followup_actions": [
            {"action": "Victim Fund Deposit Encouragement", "probability_percent": 93},
            {"action": "Withdrawal Blocking", "probability_percent": 90},
            {"action": "Mule Account Recruitment for Laundering", "probability_percent": 68}
        ]
    },
]

# Compliance / regulatory snippets (second knowledge base, optional layer)
COMPLIANCE_SNIPPETS = [
    {
        "id": "rbi_001",
        "title": "RBI Guidelines on Digital Lending Apps (2022)",
        "text": (
            "Reserve Bank of India guidelines on digital lending mandate that lending apps must not access "
            "contact lists, call logs, photos, or media files on a borrower's device except with explicit, "
            "specific consent for each data category, and such access must not be a precondition for loan "
            "disbursal. Apps found harvesting contact lists or call logs prior to or independent of loan "
            "approval are in violation of these guidelines."
        ),
        "applicable_behaviors": ["contact_harvesting", "call_log_exfiltration", "premature_data_collection"]
    },
    {
        "id": "rbi_002",
        "title": "RBI Master Direction on Digital Payment Security Controls",
        "text": (
            "Banks and payment system providers must ensure that mobile banking applications implement "
            "secure SMS-based OTP handling using restricted APIs (such as the SMS Retriever API) that do not "
            "require broad SMS read permissions. Applications requesting unrestricted READ_SMS or "
            "RECEIVE_SMS permissions for OTP-related functionality represent a security control gap and "
            "potential fraud vector under these directions."
        ),
        "applicable_behaviors": ["otp_interception", "sms_interception", "sms_otp_access"]
    },
    {
        "id": "rbi_003",
        "title": "CERT-In Advisory on Android Banking Trojans (Accessibility Service Abuse)",
        "text": (
            "CERT-In has advised that applications requesting BIND_ACCESSIBILITY_SERVICE permission "
            "without a legitimate accessibility-related function (such as screen readers for visually "
            "impaired users) should be treated as high-risk, as this permission is the primary enabler of "
            "screen overlay attacks, credential theft, and unauthorized transaction execution on banking "
            "applications."
        ),
        "applicable_behaviors": ["accessibility_abuse", "overlay_attack", "remote_access_capability"]
    },
    {
        "id": "rbi_004",
        "title": "RBI Circular on Customer Protection - Limiting Liability in Unauthorized Transactions",
        "text": (
            "Where an unauthorized electronic banking transaction occurs due to a third-party breach "
            "involving malware that the customer could not reasonably have detected (e.g., sophisticated "
            "overlay attacks or accessibility-service-based session hijacking), and the customer reports "
            "the transaction within the prescribed window, the customer's liability is limited as per RBI's "
            "customer protection framework for unauthorized digital transactions."
        ),
        "applicable_behaviors": ["overlay_attack", "remote_access_capability", "session_cookie_theft", "banking_session_hijack"]
    },
    {
        "id": "rbi_005",
        "title": "CERT-In Advisory on Notification Listener Service Misuse",
        "text": (
            "CERT-In has flagged that applications requesting BIND_NOTIFICATION_LISTENER_SERVICE permission "
            "to read notification content from other applications - particularly banking and financial "
            "applications - without a clear, disclosed, user-facing purpose constitute a high-risk pattern "
            "associated with interception of one-time passwords and transaction alerts delivered via push "
            "notifications."
        ),
        "applicable_behaviors": ["notification_listener_abuse", "otp_interception"]
    },
    {
        "id": "rbi_006",
        "title": "RBI Advisory on Fake Investment and Trading Applications",
        "text": (
            "RBI and SEBI have jointly advised the public regarding unregistered investment and trading "
            "applications that display fabricated returns to encourage deposits while blocking or delaying "
            "withdrawals. Such applications often operate as part of organized financial fraud networks and "
            "may involve recruiting depositors' bank accounts as conduits (mule accounts) for layering and "
            "laundering fraudulently obtained funds."
        ),
        "applicable_behaviors": ["fake_financial_data", "withdrawal_blocking", "mule_recruitment_pattern"]
    },
]

# MITRE ATT&CK for Mobile technique snippets (for kill-chain narrative)
ATTACK_TECHNIQUES = [
    {
        "id": "T1517",
        "name": "Access Notifications",
        "description": "Adversaries may access notification content to gather sensitive information such as one-time passwords, banking alerts, and authentication codes delivered via push notifications.",
        "applicable_behaviors": ["notification_listener_abuse"]
    },
    {
        "id": "T1414",
        "name": "Application Discovery / SMS Interception",
        "description": "Adversaries may intercept SMS messages on a device to obtain one-time passwords, authentication codes, or other sensitive information transmitted via SMS.",
        "applicable_behaviors": ["otp_interception", "sms_interception", "sms_otp_access"]
    },
    {
        "id": "T1437",
        "name": "Application Layer Protocol / C2 Communication",
        "description": "Adversaries may use application layer protocols to communicate with a command and control server, often disguising traffic as legitimate API calls (e.g., messaging bot APIs) to avoid detection.",
        "applicable_behaviors": ["c2_communication", "dga_c2_communication", "encrypted_exfiltration", "realtime_exfiltration"]
    },
    {
        "id": "T1407",
        "name": "Download New Code at Runtime",
        "description": "Adversaries may download and execute dynamic code post-installation to evade static analysis and app store review, often used by dropper-stage malware.",
        "applicable_behaviors": ["dropper_behavior", "delayed_activation", "second_stage_payload"]
    },
    {
        "id": "T1411",
        "name": "Input Prompt / Overlay Attack",
        "description": "Adversaries may display a fake input prompt or overlay on top of a legitimate application to capture user credentials, mimicking the legitimate app's UI.",
        "applicable_behaviors": ["overlay_attack", "dynamic_overlay_fetch", "ui_clone_phishing"]
    },
    {
        "id": "T1056",
        "name": "Input Capture / Keylogging",
        "description": "Adversaries may abuse accessibility services to log keystrokes and capture user input across applications, including banking credentials.",
        "applicable_behaviors": ["keylogging", "accessibility_abuse"]
    },
    {
        "id": "T1604",
        "name": "Proxy Through Victim / Remote Access",
        "description": "Adversaries may use accessibility services to gain near-complete remote control of a device, performing actions such as navigating apps and confirming transactions as if they were the device owner.",
        "applicable_behaviors": ["remote_access_capability", "live_screen_streaming"]
    },
    {
        "id": "T1418",
        "name": "Application Discovery",
        "description": "Adversaries may enumerate installed applications to identify targeted banking, financial, or cryptocurrency wallet apps for follow-on overlay or injection attacks.",
        "applicable_behaviors": ["app_enumeration"]
    },
    {
        "id": "T1532",
        "name": "Archive Collected Data / Data Exfiltration",
        "description": "Adversaries may compress, encode, or batch collected data such as credentials, contacts, or session tokens prior to exfiltration to a remote server.",
        "applicable_behaviors": ["data_exfiltration", "contact_harvesting", "call_log_exfiltration", "communication_exfiltration"]
    },
    {
        "id": "T1626",
        "name": "Abuse Elevated Privilege - Device Administrator",
        "description": "Adversaries may request Device Administrator privileges to prevent uninstallation, enforce password policies, or lock the device remotely as part of a ransomware or persistence strategy.",
        "applicable_behaviors": ["device_admin_abuse", "ransomware_module", "uninstall_prevention"]
    },
    {
        "id": "T1430",
        "name": "Location Tracking",
        "description": "Adversaries may continuously access device location data for surveillance purposes, often paired with other spyware capabilities.",
        "applicable_behaviors": ["location_tracking", "surveillance_capability"]
    },
    {
        "id": "T1409",
        "name": "Stored Application Data / Session Token Theft",
        "description": "Adversaries may access stored session cookies or authentication tokens from browser or app storage to hijack authenticated sessions without needing credentials.",
        "applicable_behaviors": ["session_cookie_theft", "banking_session_hijack"]
    },
    {
        "id": "T1417",
        "name": "Input Capture - Clipboard Data",
        "description": "Adversaries may monitor and modify clipboard contents, commonly used to swap cryptocurrency wallet addresses copied by the user with attacker-controlled addresses.",
        "applicable_behaviors": ["clipboard_hijacking"]
    },
    {
        "id": "T1582",
        "name": "SMS Control / Worm Propagation",
        "description": "Adversaries may use SMS sending capabilities to self-propagate by sending malicious links to all contacts in the victim's address book.",
        "applicable_behaviors": ["sms_worm_propagation"]
    },
]
