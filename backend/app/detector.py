"""Deterministic scam-pattern detection.

This module is the single source of truth for the risk score. The AI layer
only explains what is found here; it never changes the score.
"""

import re
from typing import Any
from urllib.parse import urlparse


# Bare domains (no scheme, no "www.") are only treated as URLs when they end in
# a plausible top-level domain. Without this, text such as "e.g", "Dr.Sharma" or
# "photo.jpg" would be reported as links.
_TLDS = (
    "com|in|net|org|info|biz|co|io|me|us|uk|ai|app|dev|xyz|online|site|website|"
    "top|club|live|shop|store|link|click|vip|icu|cfd|sbs|buzz|cc|tk|ml|ga|cf|gq|"
    "ly|gl|to|ws|pw|gov|edu|nic|ac|work|life|today|world|fun|one|bank|pay|cloud|"
    "page|tech|space|help|support|services|finance|money|cash|loan|ru|cn|pk"
)

URL_PATTERN = re.compile(
    r"""(?ix)
    (?:
        https?://[^\s<>"']+
        |
        www\.[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/[^\s<>"']*)?
        |
        (?<![@\w.\-/])
        [a-z0-9](?:[a-z0-9-]*[a-z0-9])?
        (?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*
        \.(?:%s)\b
        (?::\d{1,5})?
        (?:/[^\s<>"']*)?
    )
    """
    % _TLDS
)

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
    "ow.ly",
    "buff.ly",
    "tiny.cc",
    "lnkd.in",
}

# --------------------------------------------------------------------------
# Protective statements
# --------------------------------------------------------------------------
# Genuine bank/OTP messages contain sentences such as "Do not share your OTP
# with anyone". Those mention credentials but warn against sharing them, so a
# rule match that overlaps one of these spans is ignored.
#
# A span stops at punctuation or at "and/but/then", so a scammer's
# "Do not tell anyone and share your OTP" still has its second half evaluated.
_CLAUSE_END = r"(?=[.!?;,\n।]|\s+(?:and|but|then|aur|lekin|phir)\s|$)"
_ACTION = (
    r"(?:share|disclose|reveal|give|tell|provide|send|enter|forward|read\s*out|"
    r"install|download|click|open|scan|approve|pay|call|reply)"
)

PROTECTIVE_PATTERNS = [
    re.compile(
        rf"(?:do\s*not|don'?t|dont|never)\s+(?:ever\s+)?{_ACTION}\b[^.!?;,\n।]*?{_CLAUSE_END}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:should|must|can)\s*(?:not|'t|never)\s+be\s+(?:shared|disclosed|given|revealed)\b[^.!?;,\n।]*?{_CLAUSE_END}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:bank|we|company|team|staff)\s+(?:will\s+)?never\s+(?:asks?|requests?|calls?)\b[^.!?;,\n।]*?{_CLAUSE_END}",
        re.IGNORECASE,
    ),
    # "Share it only with the delivery partner" / "share OTP to start the trip"
    re.compile(
        rf"\b(?:share|give|tell)\b[^.!?;,\n।]{{0,30}}\b(?:only\s+with|with)\s+(?:the\s+|your\s+)?(?:delivery|driver|rider|captain|partner)\b[^.!?;,\n।]*?{_CLAUSE_END}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:share|give|tell)\b[^.!?;,\n।]{{0,30}}\bto\s+start\s+(?:the\s+|your\s+)?(?:trip|ride|delivery)\b[^.!?;,\n।]*?{_CLAUSE_END}",
        re.IGNORECASE,
    ),
    # Roman Hindi: "kisi ko na batayein", "share mat karo", "OTP share na karein"
    re.compile(
        rf"\bkisi(?:\s+ko|\s+ke\s+saath|\s+se)?\s+(?:bhi\s+)?(?:na|nahi|nahin|mat)\s+\w+[^.!?;,\n।]*?{_CLAUSE_END}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:share|bata\w*|bhej\w*|de\w*)\s+(?:na|mat)\s+(?:kare\w*|karo|kijiye|karna)\b[^.!?;,\n।]*?{_CLAUSE_END}",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:na|mat)\s+(?:share|bata\w*|bhej\w*|install|click|download)\b[^.!?;,\n।]*?{_CLAUSE_END}",
        re.IGNORECASE,
    ),
    # Devanagari. \b is unreliable around combining marks, so use lookarounds.
    re.compile(
        r"(?<![ऀ-ॿ])(?:किसी[^.!?;,\n।]{0,30}?)?(?:साझा|शेयर|बताएं|बताएँ|बताइए|भेजें|इंस्टॉल|क्लिक)\s*(?:न|ना|नहीं|मत)(?:\s*(?:करें|कीजिए|करना|करिए))?",
    ),
    re.compile(
        r"(?<![ऀ-ॿ])(?:न|ना|मत)\s+(?:बताएं|बताएँ|बताइए|भेजें|साझा|शेयर|इंस्टॉल|क्लिक)[^.!?;,\n।]*",
    ),
]

# An OTP delivery message ("482913 is your OTP ...") legitimately tells the
# recipient to enter the code in the app, so only an explicit request to hand the
# code to someone counts as a credential request.
OTP_DELIVERY_PATTERN = re.compile(
    r"(?:\b\d{4,8}\b[^.\n]{0,60}\b(?:otp|code|passcode)\b|\b(?:otp|code|passcode)\b[^.\n]{0,30}?(?:\bis\b|:)\s*\d{4,8}\b)",
    re.IGNORECASE,
)

_DISCLOSE = (
    r"(?:share|send|tell|provide|give|read\s*out|forward|text|reply\s+with|"
    r"bhejo|bhej\s*do|batao|bata\s*do|bata\s*dein|bataiye|share\s*karo|share\s*karein)"
)

CREDENTIAL_DISCLOSURE_PATTERNS = [
    rf"\b{_DISCLOSE}\b.{{0,45}}\b(?:otp|password|passwd|pin|cvv|credentials?)\b",
    rf"\b(?:otp|password|pin|cvv)\b.{{0,45}}\b{_DISCLOSE}\b",
    r"(?:ओटीपी|otp).{0,35}(?:भेजें|बताएं|शेयर|बताइए)",
    r"(?:पासवर्ड|पिन).{0,35}(?:भेजें|बताएं|शेयर)",
]

# --------------------------------------------------------------------------
# Safety net for scam styles that no specific rule describes. It does not look
# for one trick; it looks for a harmful ask (money or private details) that
# comes with pressure, a threat, a reward or a push to a link/call/app. Several
# ordinary messages contain one of these; scams usually combine them.
# --------------------------------------------------------------------------
_AMOUNT = r"(?:rs\.?|inr|\u20b9|rupees?|\$)\s?[\d,]+|\d[\d,]{2,}\s?(?:rs\.?|rupees?|\u20b9)"

GENERIC_SIGNALS: dict[str, list[str]] = {
    "money": [
        rf"\b(?:pay|send|sent|transfer|deposit|return|recharge|invest|remit|google\s*pay|gpay|phonepe)\b.{{0,45}}(?:{_AMOUNT})",
        rf"(?:{_AMOUNT}).{{0,45}}\b(?:pay|send|transfer|deposit|fee|fees|charges?|clearance|processing|membership|registration)\b",
        r"\b(?:pay|send|transfer|deposit)\b.{0,25}\b(?:fee|fees|charges?|amount|money|advance)\b",
        r"\b(?:pay|bhej|bhejo|jama|transfer|google\s*pay|gpay|phonepe)\s*(?:kar|karo|karein|kar\s*de|kardo)\b",
        r"(?:जमा|भेजें|भुगतान).{0,25}(?:रुपये|रु|फीस|शुल्क)|(?:रुपये|फीस|शुल्क).{0,25}(?:जमा|भेजें|भुगतान)",
    ],
    "info": [
        r"\b(?:photo|picture|image|screenshot)\b.{0,30}\b(?:debit|credit|atm)\s*card\b|\b\d\s*digit\s*(?:code|number)\b",
        r"\b(?:share|send|enter|confirm|verify|update|provide|submit|give|tell|read\s*out)\b.{0,45}\b(?:otp|pin|cvv|password|card\s*number|aadhaar|aadhar|pan\b|bank\s*details|account\s*number|expiry|(?:\d+\s*digit\s*)?code)\b",
        r"\b(?:otp|pin|cvv|password|card\s*number|aadhaar|aadhar|bank\s*details|account\s*number)\b.{0,35}\b(?:share|send|enter|confirm|batayein|bataiye|bhejo|daalein|daalo|photo)\b",
        r"\b(?:aadhaar|aadhar|pan|otp|pin|account)\s*(?:number|card)?\b.{0,25}\b(?:batayein|bataiye|batao|bhejein|bhejo)\b",
        r"(?:ओटीपी|पासवर्ड|पिन|आधार|खाता\s*नंबर).{0,30}(?:भेजें|बताएं|बताइए|दर्ज|शेयर)",
    ],
    "threat": [
        r"\b(?:blocked|suspended?|frozen|freeze|deactivated|cancell?ed|blacklisted|seized|disconnected|expire[sd]?|terminated)\b",
        r"\b(?:arrest|warrant|legal\s+notice|court|police\s+case|fir)\b",
        r"\bor\s+(?:we|i)\s+will\s+(?:send|share|post|leak|publish|report)\b|\bsend\s+(?:it|this|them)\s+to\s+all\s+your\s+contacts\b",
        r"\b(?:band|block|cancel|kat|cut)\s+(?:ho|ho\s+jayega|ho\s+jayegi|ho\s+jaega|ho\s+jane|hone)\b|\bwarna\b|\bnahi\s+to\b",
        r"(?:बंद\s+हो|ब्लॉक\s+हो|रद्द\s+हो|गिरफ्तार)",
    ],
    "urgency": [
        r"\b(?:urgent(?:ly)?|immediately|right\s+now|asap|last\s+warning|final\s+notice|(?:within|in)\s+\d+\s*(?:hours?|hrs|minutes?|mins)|today|tonight|\bnow\b)\b",
        r"\b(?:turant|abhi|aaj\s+hi|aaj\s+raat|jaldi)\b",
        r"(?:तुरंत|अभी|आज\s+ही|जल्दी)",
    ],
    "reward": [
        r"\b(?:won|winner|prize|lottery|jackpot|pre-?approved|guaranteed|cashback|voucher|profit|returns?|get\s+rs|earn(?:ing)?)\b",
        r"\bfree\b.{0,25}\b(?:rs|gift|voucher|offer|recharge|iphone)\b",
        r"(?:लॉटरी|इनाम|जीता|मुफ़्त|मुफ्त)",
    ],
    "action": [
        r"\b(?:click|tap|open\s+the\s+link|visit|download|install|scan|anydesk|teamviewer|join\s+(?:our|the|my)|call\s+(?:this\s+)?(?:number|now|us)|whatsapp|telegram|reply\s+with|contact\s+(?:us|mr|ms|me))\b",
        r"\b(?:qr\s*code|qr)\b",
        r"\bcall\s+(?:on\s+)?\+?\d[\d\s-]{6,}",
        r"\bcall\s+(?:kar|karke|karo|karein)\b|\d{8,}\s+par\s+call",
        r"\b(?:recharge|re-?register|update|link|verify)\s+now\b|\bclick\s+here\b",
        r"(?:क्लिक|कॉल\s+करें|लिंक)",
    ],
}

GENERIC_LABELS = ("money", "info", "threat", "urgency", "reward", "action")


def generic_signals(scan_text: str, protected: list[tuple[int, int]], has_url: bool) -> tuple[dict[str, re.Match[str]], int, int]:
    """Find which generic signal groups appear. Returns (matches, points, count)."""
    found: dict[str, re.Match[str]] = {}

    for name, patterns in GENERIC_SIGNALS.items():
        match = _first_unprotected_match(patterns, scan_text, protected)
        if match is not None:
            found[name] = match

    if has_url and "action" not in found:
        found["action"] = re.search(r"", scan_text)  # a link in the message counts as a push to act

    count = len(found)
    harmful = "money" in found or "info" in found
    pressure = "urgency" in found or "threat" in found

    points = 0
    if harmful and pressure:
        points = 30 if count < 4 else 45
    elif harmful and count >= 3:
        points = 30
    elif "threat" in found and "action" in found and "urgency" in found:
        points = 25

    return found, points, count


RULES = {
    "credentials": {
        "weight": 40,
        "patterns": [
            r"\bone[\s-]*time[\s-]*(?:password|passcode)\b.{0,45}\b(?:share|send|tell|enter|provide|verify|confirm)\b",
            r"\b(?:share|send|tell|enter|provide|verify|confirm)\b.{0,45}\b(?:otp|password|passwd|pin|cvv|credentials?)\b",
            r"\b(?:otp|password|pin|cvv)\b.{0,45}\b(?:share|send|tell|enter|provide|verify|confirm)\b",
            r"\b(?:banking|login|account)\s+details\b.{0,30}\b(?:share|send|tell|enter|provide|verify|confirm|update)\b",
            r"\b(?:aadhaar|aadhar|pan)\s+(?:number|details|card)\b.{0,30}\b(?:share|send|tell|enter|provide|verify|confirm|update)\b",
            r"(?:पासवर्ड|गोपनीय जानकारी).{0,35}(?:भेजें|बताएं|शेयर|दर्ज|बताइए)",
            r"(?:ओटीपी|otp).{0,35}(?:भेजें|बताएं|शेयर|दर्ज|बताइए)",
            r"(?:पासवर्ड|पिन).{0,35}(?:भेजें|बताएं|शेयर|दर्ज)",
            r"(?:otp|password|pin|cvv).{0,45}(?:bhejo|bhej do|batao|bata dein|share karo|share karein|send karo|send karein|enter karo|darj karein)",
            r"(?:bhejo|bhej do|batao|bata dein|share karo|share karein|send karo|send karein|enter karo|darj karein).{0,45}(?:otp|password|pin|cvv)",
        ],
        "indicator": "OTP, password, or sensitive credentials requested",
        "recommendation": "Never share an OTP, password, PIN, or CVV with anyone.",
    },
    "urgency": {
        "weight": 20,
        "patterns": [
            r"\b(?:immediately|urgent(?:ly)?|right away|act now|final warning)\b",
            r"\b(?:will be|has been|is being)\s+(?:blocked|suspended|closed|deactivated)\b",
            r"\b(?:avoid|prevent)\b.{0,30}\b(?:suspension|suspended|blocking|blocked|closure|deactivation)\b",
            r"\b(?:account|bank account|card|sim)\b.{0,50}\b(?:blocked|suspended|closed|deactivated)\b",
            # Roman Hindi urgency words only count next to a demanded action.
            r"\b(?:turant|abhi|jaldi|fauran)\b.{0,40}\b(?:karo|karein|kijiye|bhejo|bhej|batao|bataiye|share|verify|update|pay|click|link|otp|pin|account|khata|block|band|bandh)\b",
            r"\b(?:karo|karein|kijiye|bhejo|bhej|batao|bataiye|share|verify|update|pay|click|otp|pin)\b.{0,40}\b(?:turant|abhi|jaldi|fauran)\b",
            r"\b(?:account|bank account|khata)\b.{0,55}\b(?:block|blocked|band|bandh|suspend|suspended)\b",
            r"\b(?:block|blocked|band|bandh|suspend|suspended)\b.{0,55}\b(?:account|bank account|khata)\b",
            r"(?:तुरंत|अभी|जल्दी|फौरन).{0,35}(?:करें|कीजिए|वरना)",
            r"(?:खाता|अकाउंट|बैंक अकाउंट).{0,35}(?:बंद|ब्लॉक|निलंबित)",
            r"(?:बंद|ब्लॉक|निलंबित).{0,35}(?:खाता|अकाउंट|बैंक अकाउंट)",
            r"(?:नहीं तो|वरना).{0,35}(?:बंद|ब्लॉक|कार्रवाई)",
        ],
        "indicator": "Urgent or threatening language used to pressure you",
        "recommendation": "Do not act under pressure; verify the request independently.",
    },
    "money_or_prize": {
        "weight": 35,
        "patterns": [
            r"\b(?:winner|prize|lottery|reward money|claim your reward)\b",
            r"\b(?:processing|registration|release|claim)\s+fee\b",
            r"\b(?:pay|transfer|deposit|send)\b.{0,40}\b(?:processing|registration|release|clearance|customs|handling|advance|claim|insurance)\s+(?:fee|fees|charges?)\b",
            r"\b(?:pay|send|transfer)\b.{0,40}\b(?:tax|gst|charges?)\b.{0,40}\bto\s+(?:receive|claim|release|get)\b",
            # "refund"/"cashback" alone is normal in genuine receipts; it only
            # counts when the message asks you to claim or act on it.
            r"\b(?:claim|get|receive|collect)\s+(?:your\s+)?(?:refund|cashback)\b",
            r"\b(?:refund|cashback)\b.{0,40}\b(?:click|link|claim|verify|upi pin|approve|otp)\b",
            r"\b(?:free gift|guaranteed return)\b",
            r"\byou(?:['’]ve|\s+have)?\s+won\b.{0,60}(?:prize|gift|voucher|cash|lakh|crore|iphone|laptop|car\b|trip|jackpot|lottery|bonus|\$|₹|\brs\b)",
            r"\bcongratulations\b.{0,80}\b(?:won|winner|selected|lucky)\b",
            r"\bclaim\b.{0,40}\b(?:gift|prize|reward|voucher)\b",
            r"\b(?:jeet gaye|jeeta hai|jeete hain|jeet liya)\b.{0,60}\b(?:prize|lottery|lakh|crore|rs|rupaye|paise|gift)\b",
            r"\b(?:prize|lottery|lakh|crore|rs|rupaye|paise|gift)\b.{0,40}\b(?:jeet gaye|jeeta hai|jeete hain|jeet liya)\b",
            r"\b(?:inaam|puraskar|lottery|lucky draw|inaami)\b",
            r"\b(?:paise|paisa|rupaye|rupees)\b.{0,40}\b(?:bhejo|jama karo|pay karo|transfer karo)\b",
            r"\b(?:bhejo|jama karo|pay karo|transfer karo)\b.{0,40}\b(?:paise|paisa|rupaye|rupees|fee)\b",
            r"\b(?:processing fee|registration fee|advance fee|claim fee)\b",
            r"(?:इनाम|पुरस्कार|लॉटरी|लकी ड्रॉ)",
            r"(?:कैशबैक|रिफंड).{0,35}(?:क्लिक|लिंक|क्लेम|पिन|ओटीपी)",
            r"(?:प्रोसेसिंग फीस|रजिस्ट्रेशन फीस|फीस जमा|पैसे भेजें|रकम जमा)",
            r"(?:जीते हैं|जीत गए|इनाम पाने).{0,35}(?:फीस|पैसे|रजिस्ट्रेशन)",
        ],
        "indicator": "A prize, reward, payment, or money-transfer pattern was detected.",
        "recommendation": "Do not pay a fee or send money to claim an unexpected prize or reward.",
    },
    "impersonation": {
        "weight": 20,
        "patterns": [
            r"\b(?:rbi|income tax|police|customs|government)\b.{0,55}\b(?:verify|update|confirm|suspended|blocked|notice)\b",
            r"\b(?:i am|this is|we are|calling from)\b.{0,30}\b(?:customer care|support team|bank officer|government officer|rbi|police|cyber cell|cbi)\b",
            r"\bbank\b.{0,55}\b(?:requires?|urgent|verification|verify|confirm|update)\b",
            r"\b(?:kyc|re-?kyc)\b.{0,45}\b(?:update|expire|pending|blocked|verify)\b",
            r"\b(?:sarkar|police|adhikari|rbi)\b.{0,55}\b(?:verify|update|confirm|block|notice|jaanch)\b",
            r"\b(?:kyc|re-?kyc)\b.{0,45}\b(?:update karo|update karein|expire|band|block)\b",
            r"(?:आरबीआई|पुलिस|सरकार|अधिकारी).{0,40}(?:सत्यापन|अपडेट|कार्रवाई|ब्लॉक)",
            r"(?:केवाईसी|kyc).{0,35}(?:अपडेट|बंद|ब्लॉक|समाप्त)",
        ],
        "indicator": "The message may be impersonating a trusted organization or authority",
        "recommendation": "Contact the organization through its official app or independently verified contact details.",
    },
    "upi_payment_trick": {
        "weight": 50,
        "patterns": [
            r"\b(?:upi pin|collect request|approve payment|scan qr)\b",
            r"\b(?:receive money|get refund)\b.{0,45}\b(?:pin|qr|approve|payment)\b",
            r"\b(?:paise|paisa|rupaye|money|amount)\b.{0,30}\b(?:lene|pane|receive|milne)\b.{0,40}\b(?:pin|qr|approve)\b",
            r"\bscan\b.{0,40}\b(?:to\s+)?(?:receive|get)\b.{0,25}\b(?:payment|money|amount|advance)\b|\b(?:approve|accept)\b.{0,20}\b(?:request|collect)\b.{0,40}\b(?:pin|receive|paise)\b",
            r"\b(?:paise receive|payment receive|refund receive)\b.{0,45}\b(?:upi pin|pin|qr|approve)\b",
            r"\b(?:upi pin|pin|qr code)\b.{0,45}\b(?:daalo|dalo|bhejo|scan karo|approve karo|approve karein)\b",
            r"(?:यूपीआई पिन|क्यूआर कोड|पेमेंट रिक्वेस्ट).{0,40}(?:दर्ज|स्कैन|मंजूर|स्वीकार)",
            r"(?:पैसे प्राप्त|रिफंड पाने).{0,40}(?:पिन|क्यूआर|पेमेंट)",
        ],
        "indicator": "A potentially risky UPI payment or money-receiving instruction was detected",
        "recommendation": "Never enter your UPI PIN to receive money or approve an unknown collect request.",
    },
    "remote_access": {
        "weight": 35,
        "patterns": [
            r"\b(?:anydesk|teamviewer|remote access|screen sharing app|quick support)\b",
            r"\b(?:install|download)\b.{0,40}\bapp\b.{0,40}\b(?:support|refund|verification|bank)\b",
            r"\b(?:app install karo|app download karo)\b.{0,45}\b(?:support|refund|bank|screen share|access)\b",
            r"(?:रिमोट एक्सेस|स्क्रीन शेयरिंग|ऐप इंस्टॉल).{0,40}(?:बैंक|रिफंड|सपोर्ट|वेरिफिकेशन)",
        ],
        "indicator": "The message may request remote access to your device",
        "recommendation": "Do not install remote-access apps or share your screen with unknown people.",
    },
    "digital_arrest": {
        # "Digital arrest" is not a real legal process, so this signal alone is
        # treated as high risk.
        "weight": 50,
        "patterns": [
            r"\b(?:digital arrest|under digital arrest|police case|arrest warrant)\b",
            r"\b(?:customs parcel|illegal parcel|money laundering)\b.{0,45}\b(?:police|arrest|case|investigation)\b",
            r"\b(?:giraftari|police case)\b",
            r"(?:डिजिटल अरेस्ट|गिरफ्तारी|गिरफ्तारी वारंट|मनी लॉन्ड्रिंग)",
            r"(?:पुलिस|सीबीआई|कस्टम).{0,40}(?:गिरफ्तारी|केस|जांच|पैसे जमा)",
        ],
        "indicator": "A possible digital-arrest or law-enforcement intimidation pattern was detected",
        "recommendation": "Do not transfer money because of threats; independently contact official authorities.",
    },
    "job_task_scam": {
        "weight": 25,
        "patterns": [
            r"\b(?:part[- ]time job|task job|review and earn|like and earn|work from home)\b",
            r"\b(?:job|task|work)\b.{0,50}\b(?:deposit|recharge|registration fee|investment)\b",
            r"\b(?:job|naukri|kaam|task)\b.{0,45}\b(?:paise jama|deposit|recharge|registration fee)\b",
            r"\b(?:paise kamao|ghar baithe kaam|like karke kamao|review karke kamao)\b",
            r"\bearn(?:ing)?\b.{0,40}\b(?:daily|per day|a day|every day|weekly|per week)\b.{0,60}\b(?:lik(?:e|ing)|rat(?:e|ing)|review(?:ing)?|watch(?:ing)?|subscrib\w*|videos?|tasks?|telegram|whatsapp|typing|data entry)\b",
            r"\b(?:join|add)\b.{0,25}\b(?:telegram|whatsapp)\b.{0,25}\b(?:group|channel)\b.{0,60}\b(?:earn|income|task|job)\b",
            r"(?:पार्ट टाइम जॉब|घर बैठे काम|टास्क पूरा|नौकरी).{0,45}(?:जमा|रिचार्ज|फीस|निवेश)",
        ],
        "indicator": "A job or task offer may involve suspicious advance payments",
        "recommendation": "Verify job offers and never pay an upfront deposit to unlock tasks or earnings.",
    },
    "courier_scam": {
        "weight": 25,
        "patterns": [
            r"\b(?:parcel|courier|delivery)\b.{0,55}\b(?:held|blocked|failed|customs|address update|pay fee)\b",
            r"\b(?:parcel|courier|delivery)\b.{0,45}\b(?:link|fee|payment|address)\b",
            r"\b(?:parcel|courier|delivery)\b.{0,45}\b(?:link kholo|fee bharo|payment karo|address update)\b",
            r"(?:पार्सल|कूरियर|डिलीवरी).{0,45}(?:रुका|फेल|फीस|लिंक|पता अपडेट|कस्टम)",
        ],
        "indicator": "A possible courier or parcel scam pattern was detected",
        "recommendation": "Check delivery status through the courier's official website or app.",
    },
    "utility_disconnect": {
        # "Your power will be cut tonight unless you pay now" is a very common
        # Indian scam. A real due-date reminder has no same-day cut-off threat.
        "weight": 40,
        "patterns": [
            r"\b(?:electricity|electric|power|bijli|gas|water|meter|mseb|bescom|bses|tneb|discom|supply|connection)\b.{0,70}\b(?:disconnect\w*|cut(?:\s+off)?|terminat\w*|suspend\w*)\b.{0,70}(?:\btonight\b|\btoday\b|\bimmediately\b|\bwithin\s+\d+\s*(?:hours?|hrs|minutes?|mins)\b|\bat\s+\d{1,2}[:.]\d{2}|\bright\s+now\b|\bnow\b)",
            r"(?:\btonight\b|\btoday\b|\bimmediately\b|\bwithin\s+\d+\s*(?:hours?|hrs|minutes?|mins)\b).{0,60}\b(?:electricity|electric|power|bijli|gas|water|supply|connection)\b.{0,50}\b(?:disconnect\w*|cut(?:\s+off)?|terminat\w*|suspend\w*)\b",
            r"\b(?:bijli|light|connection|meter)\b.{0,50}\b(?:kat|kate|katt\w*|band|cut|disconnect\w*)\b.{0,40}\b(?:aaj raat|aaj|abhi|turant|jaldi)\b",
            r"(?:बिजली|कनेक्शन|मीटर).{0,50}(?:कट|बंद|काट).{0,40}(?:आज|अभी|तुरंत)",
        ],
        "indicator": "A possible fake utility-bill disconnection threat was detected",
        "recommendation": "Check your bill only in your electricity provider's official app or website, not through this message.",
    },
    "advance_fee": {
        # Genuine prizes, refunds, loans and deliveries do not need money first.
        "weight": 30,
        "patterns": [
            r"\b(?:pay|send|transfer|deposit)\b.{0,50}\b(?:fee|fees|charges?|tax)\b.{0,60}\bto\s+(?:receive|claim|release|get|unlock|withdraw)\b.{0,30}\b(?:prize|reward|lottery|winnings?|gift|refund|loan|parcel|package|amount|money|cash|salary)\b",
            r"\b(?:fee|fees|charges?|tax)\b.{0,40}\bto\s+(?:receive|claim|release|unlock|withdraw)\b.{0,30}\b(?:prize|reward|lottery|winnings?|gift|refund|loan|parcel|package|amount|money|cash|salary)\b",
            r"\b(?:parcel|courier|package|shipment)\b.{0,80}\b(?:customs|held|stuck|pending|undelivered)\b.{0,80}\b(?:pay|fee|charges?)\b",
            r"\bearn(?:ing)?\b.{0,120}\b(?:pay|deposit|send)\b.{0,40}\b(?:fee|deposit|charges?)\b",
            r"\b(?:pay|submit|send)\b.{0,15}\b(?:security\s+|refundable\s+|joining\s+)?deposit\b",
            r"\b(?:joining|refundable)\s+(?:fee|deposit)\b",
            r"\b(?:fee|charges?)\s+(?:bharo|bharein|jama karo|bhejo)\b.{0,60}\b(?:inaam|prize|lottery|refund|loan|parcel)\b",
            r"\b(?:inaam|prize|lottery|refund|loan|parcel)\b.{0,80}\b(?:fee|charges?)\s+(?:bharo|bharein|jama karo|bhejo)\b",
            r"(?:फीस|शुल्क).{0,30}(?:जमा|भेजें|भरें).{0,40}(?:इनाम|लॉटरी|रिफंड|लोन|पार्सल)",
        ],
        "indicator": "Money is requested before a prize, refund, loan, job or parcel is released",
        "recommendation": "Do not pay any fee or deposit to receive a prize, refund, loan, job or parcel.",
    },
    "family_emergency": {
        "weight": 25,
        "patterns": [
            r"\b(?:hi|hello)\s+(?:mom|mum|mummy|dad|papa|maa|beta)\b.{0,120}\b(?:new number|lost my phone|changed my number|phone (?:is )?(?:broken|broke|damaged|lost))\b",
            r"\b(?:lost my phone|new number|changed my number|phone (?:is )?(?:broken|broke|damaged))\b.{0,100}\b(?:send|transfer|pay)\b.{0,40}(?:money|₹|\brs\b|\d{3,})",
            r"\b(?:naya number|phone kho gaya|phone toot gaya)\b.{0,100}\b(?:paise|rupaye|\brs\b|bhej\w*|transfer)\b",
            r"(?:नया नंबर|फोन खो गया|फोन टूट गया).{0,80}(?:पैसे|रुपये|भेज|ट्रांसफर)",
        ],
        "indicator": "A possible family-emergency money request from a new number was detected",
        "recommendation": "Call the person on their old saved number before sending any money.",
    },
}

# Official registered domains of brands that scammers imitate. A link whose
# address contains one of these names but is not on its official domain list is
# flagged as a lookalike. This is a caution, not proof that the page is fake.
BRAND_DOMAINS: dict[str, set[str]] = {
    "hdfc": {"hdfcbank.com", "hdfcbank.in", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcsec.com", "hdfcfund.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbilife.co.in", "sbimf.com", "sbi.bank.in"},
    "icici": {"icicibank.com", "icicidirect.com", "icicilombard.com", "iciciprulife.com", "icicipruamc.com"},
    "axisbank": {"axisbank.com", "axisbank.co.in"},
    "kotak": {"kotak.com", "kotak811.com"},
    "paytm": {"paytm.com", "paytmbank.com", "paytm.in"},
    "phonepe": {"phonepe.com"},
    "npci": {"npci.org.in"},
    "irctc": {"irctc.co.in", "irctc.com"},
    "uidai": {"uidai.gov.in"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "epfo": {"epfindia.gov.in", "epfo.gov.in"},
    "pnb": {"pnbindia.in", "netpnb.com", "pnb.co.in"},
    "amazon": {"amazon.in", "amazon.com", "amazon.co.uk", "amazonaws.com", "amazon.jobs"},
    "flipkart": {"flipkart.com", "flipkart.in"},
}

_SECOND_LEVEL_LABELS = {"co", "com", "org", "net", "gov", "ac", "nic", "edu", "bank"}


def registered_domain(hostname: str) -> str:
    """The domain a site owner registered, e.g. 'netbanking.hdfcbank.com' -> 'hdfcbank.com'."""
    labels = hostname.lower().split(".")

    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL_LABELS and len(labels[-1]) == 2:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def find_lookalike_link(urls: list[str]) -> str | None:
    """Return the first link that names a known brand but is not on its official domain."""
    for url in urls:
        if is_shortener(url):
            continue

        hostname = get_hostname(url)

        if not hostname:
            continue

        registered = registered_domain(hostname)
        tokens = [token for token in re.split(r"[^a-z0-9]+", hostname) if token]

        for brand, official in BRAND_DOMAINS.items():
            if registered in official:
                continue

            if len(brand) <= 3:
                named = any(token == brand or token.startswith(brand) or token.endswith(brand) for token in tokens)
            else:
                named = any(brand in token for token in tokens)

            if named:
                return url

    return None


def extract_urls(message: str) -> list[str]:
    """Extract unique URLs while preserving the original URL form."""
    if not isinstance(message, str) or not message.strip():
        return []

    found = URL_PATTERN.findall(message)
    urls: list[str] = []
    seen: set[str] = set()

    for raw_url in found:
        url = raw_url.strip().rstrip(".,!?;:)]}")

        if not url:
            continue

        # Keep www.example.com as-is for compatibility with callers/tests.
        normalized = url.lower()
        if normalized not in seen:
            seen.add(normalized)
            urls.append(url)

    return urls


def get_hostname(url: str) -> str:
    """Return a validated hostname, preserving www when present."""
    if not isinstance(url, str) or not url.strip():
        return ""

    value = url.strip()

    if any(char.isspace() for char in value):
        return ""

    if "://" not in value:
        # Reject plain words or invalid hostname-like values without a dot.
        if not value.lower().startswith("www.") and "." not in value:
            return ""
        value = "https://" + value

    try:
        parsed = urlparse(value)
        hostname = parsed.hostname or ""

        if not hostname:
            return ""

        # Validate port; accessing .port raises ValueError for invalid ports.
        _ = parsed.port

        hostname = hostname.lower()

        if "." not in hostname:
            return ""

        if hostname.startswith(".") or hostname.endswith("."):
            return ""

        if not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?",
            hostname,
        ):
            return ""

        labels = hostname.split(".")
        if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
            return ""

        return hostname

    except (TypeError, ValueError):
        return ""


def is_shortener(url: str) -> bool:
    """Check whether a URL uses a known URL-shortening service."""
    hostname = get_hostname(url)

    return any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in SHORTENER_DOMAINS
    )


def _has_invalid_url_format(message: str) -> bool:
    """Detect common malformed URLs such as a URL containing whitespace."""
    return bool(
        re.search(r"https?://\S+\s+\S+\.\S+", message, flags=re.IGNORECASE)
    )


def _protective_spans(text: str) -> list[tuple[int, int]]:
    """Return spans of sentences that warn the reader NOT to do something risky."""
    spans: list[tuple[int, int]] = []
    for pattern in PROTECTIVE_PATTERNS:
        for match in pattern.finditer(text):
            spans.append(match.span())
    return spans


def _overlaps(span: tuple[int, int], others: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(start < o_end and o_start < end for o_start, o_end in others)


def is_otp_delivery_message(text: str) -> bool:
    """True for messages that deliver a code, e.g. '482913 is your OTP'."""
    return bool(OTP_DELIVERY_PATTERN.search(text))


def _first_unprotected_match(
    patterns: list[str],
    text: str,
    protected: list[tuple[int, int]],
) -> re.Match[str] | None:
    """First pattern match that is not part of a protective warning."""
    for pattern in patterns:
        compiled = re.compile(pattern, re.IGNORECASE)
        position = 0

        while position <= len(text):
            match = compiled.search(text, position)

            if match is None:
                break

            if not _overlaps(match.span(), protected):
                return match

            # The match touched a protective sentence. Retry from the next
            # character so a genuine request that follows is not hidden behind
            # an overlapping, longer match.
            position = match.start() + 1

    return None


def _snippet(text: str, match: re.Match[str], limit: int = 90) -> str:
    """Return the matched wording from the user's message, shortened if needed."""
    snippet = re.sub(r"\s+", " ", text[match.start():match.end()]).strip()
    if len(snippet) > limit:
        snippet = snippet[: limit - 1].rstrip() + "…"
    return snippet


def analyze_message(message: str) -> dict[str, Any]:
    """Analyze a message using deterministic scam-pattern rules."""
    if not isinstance(message, str) or not message.strip():
        return {
            "risk_score": 0,
            "risk_level": "low",
            "indicators": [],
            "matched_categories": [],
            "findings": [],
            "recommendations": ["Enter a message to analyze."],
            "assessment_note": (
                "This heuristic score reflects patterns found in the message; "
                "it is not a probability that a message is a scam."
            ),
            "urls": [],
        }

    text = message.strip()

    # Wording rules run on the text with URLs blanked out. Words inside a domain
    # (for example the "kyc-update" in sbi-kyc-update.xyz) are not statements the
    # sender made, and the URL has its own signal and reputation check below.
    scan_text = URL_PATTERN.sub(lambda m: " " * len(m.group(0)), text)

    score = 0
    indicators: list[str] = []
    matched_categories: list[str] = []
    findings: list[dict[str, str]] = []
    recommendations: list[str] = []

    protected = _protective_spans(scan_text)
    otp_delivery = is_otp_delivery_message(scan_text)

    for category, rule in RULES.items():
        patterns = rule["patterns"]

        if category == "credentials" and otp_delivery:
            # A message that simply delivers a code only counts when it also
            # asks the reader to hand the code to someone.
            patterns = CREDENTIAL_DISCLOSURE_PATTERNS

        match = _first_unprotected_match(patterns, scan_text, protected)

        if match is None:
            continue

        score += rule["weight"]
        matched_categories.append(category)
        indicators.append(rule["indicator"])
        recommendations.append(rule["recommendation"])
        findings.append({"category": category, "evidence": _snippet(scan_text, match)})

    urls = extract_urls(text)

    if urls:
        score += 10
        indicators.append(
            "The URL destination has not been verified."
        )
        recommendations.append(
            "Verify the website domain before opening links or entering personal details."
        )
        findings.append({"category": "url", "evidence": urls[0]})

    lookalike = find_lookalike_link(urls)

    if lookalike:
        score += 25
        matched_categories.append("lookalike_domain")
        indicators.append("A link address contains a known brand name but is not that brand's official domain.")
        recommendations.append("Do not open the link; type the official website address yourself.")
        evidence = lookalike if len(lookalike) <= 90 else lookalike[:89] + "…"
        findings.append({"category": "lookalike_domain", "evidence": evidence})

    shortened = [url for url in urls if is_shortener(url)]

    if shortened:
        score += 15
        indicators.append(
            "A URL-shortening service was detected."
        )
        recommendations.append(
            "Avoid opening shortened links unless you can verify their destination."
        )
        findings.append({"category": "short_url", "evidence": shortened[0]})

    # Safety net: only when the specific rules did not already reach High.
    if score < 50:
        sigs, points, _count = generic_signals(scan_text, protected, bool(urls))

        if points:
            score += points
            matched_categories.append("generic_scam_pattern")
            indicators.append("Several warning signs that scams often combine were found together")
            recommendations.append("Do not act on this message. Check it through the sender's official app, website or number.")
            lead = next((sigs[k] for k in ("info", "money", "threat", "reward", "urgency", "action") if k in sigs and sigs[k].group(0).strip()), None)
            evidence = _snippet(scan_text, lead) if lead is not None else ""
            findings.append({"category": "generic_scam_pattern", "evidence": evidence})

    if _has_invalid_url_format(text):
        indicators.append(
            "The URL has an invalid or unsupported format."
        )

    score = min(score, 100)

    if score >= 50:
        risk_level = "high"
    elif score >= 25:
        risk_level = "medium"
    else:
        risk_level = "low"

    if not indicators:
        indicators = ["No configured scam indicators were detected."]

    # Do not attach generic scam advice to every ordinary message. Recommendations
    # should be tied to an actual matched category or URL finding.
    recommendations = list(dict.fromkeys(recommendations))

    assessment_note = (
        "This heuristic score reflects patterns found in the message; "
        "it is not a probability that the message is a scam. A low score "
        "or an unflagged URL does not prove a message or website is safe. "
        "New or unusual scam patterns may be missed."
    )

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "matched_categories": matched_categories,
        "findings": findings,
        "recommendations": recommendations,
        "assessment_note": assessment_note,
        "urls": urls,
    }
