"""
Rule-based phishing email analyzer.

This module contains no machine learning — it scores an email against a set
of heuristics commonly used to spot phishing attempts. Each rule that fires
contributes weighted points to a 0-100 risk score.
"""

import re
from urllib.parse import urlparse

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "rebrand.ly", "cutt.ly", "shorte.st",
]

URGENT_PHRASES = [
    "act now", "immediate action", "urgent", "verify your account",
    "account suspended", "account will be closed", "confirm your identity",
    "unusual activity", "click here immediately", "limited time",
    "failure to comply", "your account has been locked", "final notice",
    "action required", "update your information", "avoid suspension",
    "within 24 hours", "expire",
]

SENSITIVE_REQUESTS = [
    "password", "social security", "ssn", "credit card", "bank account",
    "routing number", "cvv", "pin number", "login credentials",
    "wire transfer", "confirm your password",
]

TRUSTED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "bank of america", "chase", "wells fargo", "irs", "usps", "fedex",
    "dhl", "linkedin",
]

FREE_MAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]

URL_REGEX = re.compile(r"(https?://[^\s<>\"')]+)", re.IGNORECASE)
FROM_REGEX = re.compile(r"from:\s*(.+)", re.IGNORECASE)
EMAIL_ADDR_REGEX = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
EXCLAIM_RUN_REGEX = re.compile(r"!{2,}")
QUESTION_RUN_REGEX = re.compile(r"\?{2,}")
CAPS_WORD_REGEX = re.compile(r"\b[A-Z]{4,}\b")
GENERIC_GREETING_REGEX = re.compile(
    r"dear (customer|user|valued customer|member|account holder)", re.IGNORECASE
)


def _severity_rank(sev):
    return {"high": 3, "med": 2, "low": 1}.get(sev, 0)


def analyze_email(text: str) -> dict:
    findings = []
    lower = text.lower()

    # 1. Urgency / pressure language
    for phrase in URGENT_PHRASES:
        idx = lower.find(phrase)
        if idx != -1:
            findings.append({
                "tag": "URGENCY",
                "weight": 8,
                "severity": "med",
                "detail": (
                    f'Pressure language detected: "{text[idx:idx+len(phrase)]}". '
                    "Phishing emails often create false urgency to short-circuit "
                    "careful thinking."
                ),
            })

    # 2. Requests for sensitive info
    for term in SENSITIVE_REQUESTS:
        idx = lower.find(term)
        if idx != -1:
            findings.append({
                "tag": "SENSITIVE REQUEST",
                "weight": 15,
                "severity": "high",
                "detail": (
                    f'Mentions "{text[idx:idx+len(term)]}". Legitimate organizations '
                    "rarely ask you to send or confirm this over email."
                ),
            })

    # 3. URLs
    urls = URL_REGEX.findall(text)
    for url in urls:
        try:
            hostname = urlparse(url).hostname or url
        except ValueError:
            hostname = url
        hostname = hostname.lower()

        if any(s in hostname for s in SHORTENERS):
            findings.append({
                "tag": "SHORTENED LINK",
                "weight": 12,
                "severity": "high",
                "detail": f"Link uses a URL shortener ({hostname}), which hides the real destination.",
            })

        for brand in TRUSTED_BRANDS:
            brand_no_space = brand.replace(" ", "")
            if brand_no_space in hostname and not hostname.endswith(brand_no_space + ".com"):
                findings.append({
                    "tag": "SPOOFED DOMAIN",
                    "weight": 18,
                    "severity": "high",
                    "detail": (
                        f'Link domain "{hostname}" references "{brand}" but doesn\'t '
                        f"match {brand}'s real domain — a common impersonation trick."
                    ),
                })

        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname):
            findings.append({
                "tag": "RAW IP LINK",
                "weight": 15,
                "severity": "high",
                "detail": f"Link points directly to an IP address ({hostname}) instead of a domain name — rarely legitimate.",
            })

    if len(urls) > 3:
        findings.append({
            "tag": "LINK VOLUME",
            "weight": 5,
            "severity": "low",
            "detail": f"Email contains {len(urls)} links, which is unusually high for a routine message.",
        })

    # 4. Sender / From: mismatch
    from_match = FROM_REGEX.search(text)
    if from_match:
        from_line = from_match.group(1)
        email_match = EMAIL_ADDR_REGEX.search(from_line)
        if email_match:
            sender_domain = email_match.group(0).split("@")[1].lower()
            display_name = from_line.replace(email_match.group(0), "").lower()

            for brand in TRUSTED_BRANDS:
                brand_no_space = brand.replace(" ", "")
                if brand in display_name and brand_no_space not in sender_domain:
                    findings.append({
                        "tag": "SENDER MISMATCH",
                        "weight": 18,
                        "severity": "high",
                        "detail": (
                            f'Display name references "{brand}" but the actual sender '
                            f'address domain is "{sender_domain}" — a classic spoofing pattern.'
                        ),
                    })

            if sender_domain in FREE_MAIL_DOMAINS and any(b in display_name for b in TRUSTED_BRANDS):
                findings.append({
                    "tag": "FREE EMAIL SENDER",
                    "weight": 10,
                    "severity": "med",
                    "detail": f"Claims to be from a known company but sent from a free email provider ({sender_domain}).",
                })

    # 5. Excessive punctuation
    exclaim_run = EXCLAIM_RUN_REGEX.search(text)
    question_run = QUESTION_RUN_REGEX.search(text)
    if exclaim_run or question_run:
        example = (exclaim_run or question_run).group(0)
        findings.append({
            "tag": "PUNCTUATION",
            "weight": 5,
            "severity": "low",
            "detail": f'Excessive punctuation detected (e.g. "{example}"), often used to create alarm.',
        })

    # 6. ALL CAPS words
    caps_words = [w for w in CAPS_WORD_REGEX.findall(text) if w not in ("FROM", "SUBJECT", "DATE")]
    if len(caps_words) >= 2:
        unique_caps = list(dict.fromkeys(caps_words))[:4]
        findings.append({
            "tag": "ALL CAPS",
            "weight": 6,
            "severity": "low",
            "detail": f"Multiple all-caps words detected ({', '.join(unique_caps)}), a common attention-grabbing tactic.",
        })

    # 7. Generic greeting
    if GENERIC_GREETING_REGEX.search(text):
        findings.append({
            "tag": "GENERIC GREETING",
            "weight": 6,
            "severity": "low",
            "detail": "Uses a generic greeting instead of your name, suggesting a mass-sent message.",
        })

    findings.sort(key=lambda f: _severity_rank(f["severity"]), reverse=True)

    raw_score = sum(f["weight"] for f in findings)
    score = min(100, raw_score)

    if score < 25:
        verdict = "Likely Safe"
    elif score < 55:
        verdict = "Suspicious — Review Carefully"
    else:
        verdict = "Potential Phishing"

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings,
    }
