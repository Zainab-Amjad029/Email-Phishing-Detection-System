import re
from urllib.parse import urlparse

try:
    from url_reputation_checker import URLReputationChecker
    URL_REPUTATION_AVAILABLE = True
except ImportError:
    URL_REPUTATION_AVAILABLE = False

KEYWORDS = [
    "verify",
    "password",
    "urgent",
    "winner",
    "click",
    "claim",
    "login",
    "verify now",
    "update your",
    "secure your",
    "reset your",
    "confirm your",
    "payment",
    "invoice",
    "billing",
    "unsubscribe",
    "limited time",
    "action required",
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
]

SUSPICIOUS_PHRASES = {
    "click here": 15,
    "verify your account": 20,
    "update your account": 20,
    "secure your account": 20,
    "confirm your identity": 20,
    "login to your": 15,
    "account suspended": 25,
    "you have won": 20,
    "urgent action required": 25,
    "final notice": 20,
    "immediate action required": 25,
    "payment required": 20,
    "verify payment": 20,
    "social security": 30,
    "credit card": 25,
    "bank account": 25,
    "security alert": 20,
}

REDACTION_PATTERNS = [
    r"\b(?:password|credentials|ssn|social security|credit card|account number|pin)\b",
    r"\b(?:click here|verify now|update now|login here|reset password|confirm details)\b",
    r"\b(?:urgent|immediately|as soon as possible|today|within 24 hours)\b",
    r"\b(?:paypal|amazon|google|apple|microsoft)\b",
]


def analyze_email(text):
    text = text or ""
    normalized = text.strip()
    lower_text = normalized.lower()

    score = 0
    reasons = []

    if not lower_text:
        return 0, ["No email content provided"], "LOW"

    # Keyword and suspicious phrase matching.
    for phrase, weight in SUSPICIOUS_PHRASES.items():
        if phrase in lower_text:
            score += weight
            reasons.append(f"Contains suspicious phrase: '{phrase}' - This is typically used to trick you into taking action")

    for word in KEYWORDS:
        if word in lower_text:
            score += 8
            reasons.append(f"Contains suspicious word: '{word}' - Commonly used in phishing to create urgency")

    # URL detection and domain checks.
    urls = re.findall(r'https?://[^\s"\)]+', normalized)
    if urls:
        score += 20
        reasons.append("Contains links - Be careful! Phishing emails often contain malicious links")
        for url in urls:
            domain = urlparse(url).netloc.lower()
            if any(short in domain for short in SHORTENERS):
                score += 25
                reasons.append(f"Uses shortened URL ({domain}) - Links can be hidden to disguise their true destination")
            if domain.endswith(".ru") or domain.endswith(".cn") or domain.endswith(".tk"):
                score += 20
                reasons.append(f"URL uses suspicious country domain (.ru/.cn/.tk) - High-risk region: {domain}")

    # Link-looking text without explicit URL.
    if re.search(r"\bwww\.[\w\-]+\.", lower_text):
        score += 15
        reasons.append("Contains link text (www...) without actual clickable link - Designed to trick you into typing in the address")

    # Credential request patterns.
    for pattern in REDACTION_PATTERNS:
        if re.search(pattern, lower_text):
            score += 12
            reasons.append("Asks for your passwords or personal info - Legitimate companies will never ask this via email")

    # High urgency or pressure tactics.
    if re.search(r"\b(urgent|immediately|as soon as possible|now|today|within 24 hours)\b", lower_text):
        score += 15
        reasons.append("Uses urgent/pressure language - Scammers create fake urgency to rush you into clicking malicious links")

    # Personal, polite wording that is more typical of genuine communication.
    personal_clues = [
        "sorry",
        "apologize",
        "grateful",
        "thank you",
        "thanks",
        "hopefully",
        "hope",
        "please",
        "my laptop",
        "technician",
        "i am",
        "i have",
        "i've",
        "i'll",
        "tomorrow",
        "due to",
    ]
    personal_matches = sum(1 for clue in personal_clues if clue in lower_text)
    if personal_matches >= 3 and not urls and all(
        phrase not in lower_text for phrase in ["password", "credentials", "verify", "login", "confirm", "account"]
    ):
        reduction = 20
        score = max(0, score - reduction)
        reasons.append("Email appears genuine - Uses personal, polite wording typical of legitimate messages")

    # Excess punctuation and capitalization.
    if normalized.count("!") >= 3:
        score += 10
        reasons.append("Multiple exclamation marks - Phishing emails use excessive punctuation to look urgent")
    if normalized.isupper() and len(normalized) > 30:
        score += 15
        reasons.append("Written in ALL-CAPS - Phishing emails often use ALL CAPS to look important and urgent")

    # Strange formatting and suspicious email structure.
    if re.search(r"\b(dear customer|dear user|valued customer|account holder|dear sir)\b", lower_text):
        score += 12
        reasons.append("Uses generic greeting (Dear Customer/User) - Real companies address you by name")
    if re.search(r"\b(click|visit|open)\b.*\b(link|below|here)\b", lower_text):
        score += 12
        reasons.append("Asks you to click or visit a link - Don't click links in suspicious emails")

    # Add a small score for lengthy suspicious content consistency.
    if len(lower_text) < 40 and re.search(r"\b(offer|free|win|winner|prize)\b", lower_text):
        score += 10
        reasons.append("Suspicious promotional offer - 'You won!' and 'Free offer!' emails are common phishing tactics")

    # --------------------
    # Bank-safe mitigation
    # --------------------
    SAFE_PHRASES = [
        "transaction",
        "statement",
        "account ending",
        "last 4",
        "approved",
        "authorization",
        "recent activity",
        "payment received",
        "balance",
        "receipt",
        "confirmation",
        "posted",
        "thank you",
        "customer service",
    ]

    # If message references bank/account but also contains legitimate-sounding phrases,
    # reduce the score to avoid false positives on real bank messages.
    bank_indicators = any([
        p in lower_text for p in ["bank", "bank of", "your bank", "account", "credit union"]
    ])
    safe_clues = any([p in lower_text for p in SAFE_PHRASES])
    if bank_indicators and safe_clues:
        reduction = 35
        score = max(0, score - reduction)
        reasons.append("Email contains legitimate banking language - Appears to be from your actual bank")

    # URL Reputation Check
    # --------------------
    if URL_REPUTATION_AVAILABLE and urls:
        try:
            checker = URLReputationChecker()
            url_check_result = checker.check_email_urls(text)
            
            if url_check_result['malicious_count'] > 0:
                score += 40  # Significant boost for malicious URLs
                reasons.append(f"🚨 URL REPUTATION: {url_check_result['malicious_count']} malicious URL(s) detected")
            
            if url_check_result['risk_score'] > 40:
                score += 20
                reasons.append(f"⚠️ URL REPUTATION: High-risk URLs detected (score: {url_check_result['risk_score']})")
            
            # Add recommendations
            reasons.extend(url_check_result['recommendations'])
        except Exception as e:
            # Fail gracefully if URL reputation check fails
            reasons.append(f"Note: URL reputation check unavailable ({str(e)[:50]}...)")

    score = min(max(score, 0), 100)

    if score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not reasons:
        reasons.append("No clear phishing indicators found")

    return score, reasons, risk_level