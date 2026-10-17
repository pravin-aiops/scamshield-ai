
import ipaddress
import re
from urllib.parse import urlsplit


URL_PATTERN = re.compile(
    r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
)

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
}

RULES = [
    {
        "name": "urgency",
        "patterns": [
            r"\bact now\b",
            r"\bimmediately\b",
            r"\bwithin \d+ hours?\b",
            r"\baccount.{0,25}(?:blocked|suspended|will be closed)\b",
            r"\bverify.{0,25}(?:now|immediately)\b",
            r"\burgent(?:ly)?\b",
            r"\bfinal warning\b",
            r"तुरंत कार्रवाई",
            r"तुरंत करें",
            r"खाता.{0,25}(?:बंद|ब्लॉक|निलंबित|सील)",
            r"आज ही.{0,20}(?:बंद|ब्लॉक|निलंबित)",
            r"(?:बंद|ब्लॉक|निलंबित).{0,25}खाता",
            r"(?:खाता|अकाउंट).{0,35}(?:बंद हो जाएगा|बंद कर दिया जाएगा|ब्लॉक हो जाएगा|निलंबित हो जाएगा)",
            r"तुरंत.{0,20}(?:कार्रवाई|सत्यापन|वेरिफाई)",
            r"अभी.{0,20}(?:करें|भेजें|बताएं)",
        ],
        "score": 20,
        "reason": "Urgent or threatening language detected.",
    },
    {
        "name": "credentials",
        "patterns": [
            r"\bshare.{0,20}(?:otp|pin|password)\b",
            r"\b(?:otp|pin|password).{0,20}(?:share|send|provide|enter)\b",
            r"\benter your otp\b",
            r"\bconfirm your password\b",
            r"\bsend.{0,15}(?:otp|pin|password)\b",
            r"\b(?:otp|pin|password).{0,20}(?:required|needed)\b",
            r"ओटीपी.{0,30}(?:भेजें|बताएं|बताइए|साझा|दें|करें)",
            r"पासवर्ड.{0,30}(?:भेजें|बताएं|बताइए|साझा|दें|करें)",
            r"पिन.{0,30}(?:भेजें|बताएं|बताइए|साझा|दें|करें)",
            r"(?:otp|pin|password).{0,35}(?:भेजें|बताएं|बताइए|साझा|दें|करें)",
            r"(?:ओटीपी|otp|पिन|pin|पासवर्ड|password).{0,35}(?:तुरंत|अभी).{0,20}(?:भेजें|बताएं|साझा|दें|करें)",
            r"(?:साझा करें|भेजें|बताएं|बताइए|दें).{0,20}(?:ओटीपी|otp|पिन|pin|पासवर्ड|password)",
        ],
        "score": 40,
        "reason": "The message requests sensitive credentials or an OTP.",
    },
    {
        "name": "money_or_prize",
        "patterns": [
            r"\bclaim your prize\b",
            r"\byou have won\b",
            r"\bclaim your reward\b",
            r"\bpay.{0,20}(?:fee|tax|deposit)\b",
            r"\btransfer money\b",
            r"\bprocessing fee\b",
            r"\bprize money\b",
            r"\bclaim.{0,20}(?:cash|bonus|reward)\b",
            r"इनाम.{0,25}(?:जीत|प्राप्त|क्लेम|मिला|मिलने)",
            r"(?:जीत गए|जीत गई|जीत लिया|इनाम मिला)",
            r"प्रोसेसिंग फीस",
            r"(?:फीस|शुल्क|टैक्स).{0,20}(?:जमा|भेजें|भुगतान)",
            r"पैसे.{0,25}(?:भेजें|जमा करें|ट्रांसफर करें)",
            r"(?:पैसे|राशि).{0,25}(?:तुरंत|अभी).{0,20}(?:भेजें|जमा करें|ट्रांसफर करें)",
        ],
        "score": 25,
        "reason": "A prize, reward, payment, or money-transfer pattern was detected.",
    },
    {
    "name": "impersonation",
    "patterns": [
        r"\b(?:bank|government|police|customs).{0,30}(?:payment|fine|arrest|verify|urgent|immediately)\b",
        r"\b(?:official|security team|support team).{0,30}(?:verify|payment|password|otp)\b",
        r"\bkyc.{0,20}(?:update|expire|suspend)\b",
        r"बैंक.{0,25}(?:के नाम पर|बनकर|प्रतिनिधि|केवाईसी)",
        r"केवाईसी.{0,20}(?:अपडेट|समाप्त|सत्यापन)",
    ],
    "score": 20,
    "reason": "The message may be impersonating an organisation or authority.",
    },
]


def extract_urls(text: str) -> list[str]:
    """Extract HTTP(S) and www URLs from a message."""
    urls = URL_PATTERN.findall(text)

    return [
        url.rstrip(".,!?;:)]}>'\"")
        for url in urls
    ]


def get_hostname(url: str) -> str:
    """Return a syntactically valid hostname, or an empty string."""
    candidate = url.strip()

    if candidate.lower().startswith(("http://", "https://")):
        pass
    elif candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"
    else:
        return ""

    try:
        parsed = urlsplit(candidate)

        if parsed.scheme.lower() not in ("http", "https"):
            return ""

        hostname = parsed.hostname

        # Accessing .port validates the port syntax and range.
        _ = parsed.port

    except ValueError:
        return ""

    if not hostname:
        return ""

    hostname = hostname.lower().rstrip(".")

    if len(hostname) > 253:
        return ""

    # Valid IPv4 and IPv6 addresses are allowed.
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass

    labels = hostname.split(".")

    if len(labels) < 2:
        return ""

    label_pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    if any(
        not label
        or len(label) > 63
        or not label_pattern.fullmatch(label)
        for label in labels
    ):
        return ""

    return hostname


def is_shortener(hostname: str) -> bool:
    """Match known shortener domains without matching lookalike suffixes."""
    return any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in SHORTENER_DOMAINS
    )


def analyze_message(message: str) -> dict:
    text = message.strip()

    if not text:
        return {
            "risk_score": 0,
            "risk_level": "low",
            "indicators": [],
            "recommendations": ["Enter a message to analyse."],
        }

    score = 0
    indicators = []
    matched_rules = set()

    # Apply each rule once, even if several patterns match.
    for rule in RULES:
        matched = any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in rule["patterns"]
        )

        if matched:
            matched_rules.add(rule["name"])
            score += rule["score"]
            indicators.append(rule["reason"])

    urls = extract_urls(text)
    valid_hostnames = [get_hostname(url) for url in urls]
    has_url = bool(urls)
    has_shortener = any(
        is_shortener(hostname)
        for hostname in valid_hostnames
        if hostname
    )
    has_invalid_url = any(
        not hostname for hostname in valid_hostnames
    )

    if has_url:
        # A URL is not proof of fraud, but its reputation is not checked here.
        score += 10
        indicators.append(
            "The message contains a URL. Its destination has not been verified."
        )

        if has_invalid_url:
            indicators.append(
                "One or more URLs have an invalid or unsupported format."
            )

        if has_shortener:
            score += 15
            indicators.append(
                "A URL-shortening service was detected; the final destination is hidden."
            )

    score = min(score, 100)

    if score >= 50:
        risk_level = "high"
    elif score >= 25:
        risk_level = "medium"
    else:
        risk_level = "low"

    recommendations = []

    if has_url:
        recommendations.append(
            "Do not open an unexpected link until you verify its destination independently."
        )

    if "credentials" in matched_rules:
        recommendations.append(
            "Never share an OTP, PIN, or password with anyone."
        )

    if "money_or_prize" in matched_rules:
        recommendations.append(
            "Do not pay a fee or send money to claim an unexpected prize or reward."
        )

    if "urgency" in matched_rules or "impersonation" in matched_rules:
        recommendations.append(
            "Verify the claim using the organisation's official app, website, or phone number."
        )

    if not recommendations:
        recommendations.extend([
            "No strong scam patterns were detected by these rules.",
            "Still verify unexpected requests through official channels.",
        ])

    if not indicators:
        indicators.append(
            "No configured scam indicators were detected."
        )

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendations": recommendations,
    }
