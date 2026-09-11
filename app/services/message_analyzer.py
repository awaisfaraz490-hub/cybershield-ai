"""
Defensive, local heuristic message/text analyzer.

Detects common phishing/social-engineering patterns in free text
(WhatsApp/Facebook/SMS/Email/Instagram messages, or OCR-extracted text).
"""
import re

from app.services.scoring import Signal
from app.services.url_analyzer import analyze_url

URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>\")]+",
    re.IGNORECASE,
)

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediately\b", r"\bright away\b", r"\bact now\b",
    r"\btoday only\b", r"\bexpir(es|ing|ed)\b", r"\blast chance\b", r"\bhurry\b",
    r"\bwithin \d+ hours?\b", r"\bfinal (warning|notice)\b",
]

FEAR_THREAT_PATTERNS = [
    r"\baccount (will be|has been) (suspended|blocked|deleted|locked|disabled)\b",
    r"\bpermanently deleted\b", r"\blegal action\b", r"\bsuspicious activity\b",
    r"\bunauthorized (login|access)\b", r"\byour account is (at risk|compromised)\b",
]

PRIZE_SCAM_PATTERNS = [
    r"\bcongratulations\b", r"\byou('?ve| have) won\b", r"\bclaim your (prize|reward|gift)\b",
    r"\bfree (iphone|gift|prize|reward|voucher|gift card)\b", r"\blucky winner\b",
    r"\bselected (as a )?winner\b",
]

VERIFICATION_REQUEST_PATTERNS = [
    r"\bverify (your|now)\b", r"\bconfirm your (account|identity|details)\b",
    r"\breactivate your account\b", r"\bupdate your (payment|billing|account) (info|information|details)\b",
]

CREDENTIAL_REQUEST_PATTERNS = [
    r"\b(enter|send|share|provide) your password\b",
    r"\byour (password|login credentials)\b.{0,20}\b(required|needed)\b",
    r"\bcredit card (number|details)\b",
]

OTP_REQUEST_PATTERNS = [
    r"\botp\b", r"\bone[- ]time (password|code)\b", r"\bverification code\b",
    r"\bshare (the )?code\b", r"\bsend (the )?code\b",
]

PAYMENT_REQUEST_PATTERNS = [
    r"\bpay(ment)? (now|required|immediately)\b", r"\bwire transfer\b",
    r"\bgift card\b.{0,20}\bpayment\b", r"\bsend money\b", r"\bprocessing fee\b",
]

IMPERSONATION_PATTERNS = [
    r"\bofficial (whatsapp|facebook|instagram|support|team)\b",
    r"\bthis is (whatsapp|facebook|instagram|paypal|apple|microsoft|amazon) support\b",
    r"\bcustomer (support|service) team\b",
]

JOB_INVESTMENT_SCAM_PATTERNS = [
    r"\bwork from home\b.{0,20}\bearn\b", r"\bguaranteed (income|profit|returns)\b",
    r"\binvestment opportunity\b", r"\bdouble your money\b", r"\bcrypto (investment|opportunity)\b",
    r"\bpart[- ]time job\b.{0,20}\bdaily payment\b",
]

ROMANCE_FINANCIAL_SCAM_PATTERNS = [
    r"\bi (love|trust) you\b.{0,30}\bsend (me )?money\b",
    r"\bemergency\b.{0,20}\bneed money\b",
    r"\bcustoms (fee|clearance)\b",
]

CLICK_PATTERNS = [
    r"\bclick (this|the) link\b", r"\bclick here\b", r"\btap (this|the) link\b",
    r"\bfollow this link\b",
]


def _find_matches(text_lower: str, patterns: list[str]) -> list[str]:
    matches = []
    for p in patterns:
        if re.search(p, text_lower, re.IGNORECASE):
            matches.append(p)
    return matches


def extract_urls(text: str) -> list[str]:
    return list(dict.fromkeys(URL_PATTERN.findall(text)))  # de-duplicated, order preserved


def analyze_message(text: str) -> tuple[list[Signal], list[str]]:
    """
    Returns (signals, detected_urls) for a piece of free text.
    """
    signals: list[Signal] = []
    text_lower = text.lower()

    if _find_matches(text_lower, URGENCY_PATTERNS):
        signals.append(Signal("urgency_language", 10, "The message creates a sense of urgency to pressure quick action."))

    if _find_matches(text_lower, FEAR_THREAT_PATTERNS):
        signals.append(Signal("fear_threat_language", 15, "The message uses fear or threats (e.g. account suspension) to provoke a reaction."))

    if _find_matches(text_lower, PRIZE_SCAM_PATTERNS):
        signals.append(Signal("prize_scam_pattern", 15, "The message follows a common prize/reward scam pattern."))

    if _find_matches(text_lower, VERIFICATION_REQUEST_PATTERNS):
        signals.append(Signal("fake_verification_request", 15, "The message asks you to 'verify' or 'confirm' your account — a common phishing tactic."))

    if _find_matches(text_lower, CREDENTIAL_REQUEST_PATTERNS):
        signals.append(Signal("credential_request", 25, "The message appears to request a password or sensitive account credentials."))

    if _find_matches(text_lower, OTP_REQUEST_PATTERNS):
        signals.append(Signal("otp_request", 25, "The message references OTPs or verification codes, which legitimate services never ask you to share."))

    if _find_matches(text_lower, PAYMENT_REQUEST_PATTERNS):
        signals.append(Signal("suspicious_payment_request", 20, "The message requests a payment, transfer, or fee under pressure."))

    if _find_matches(text_lower, IMPERSONATION_PATTERNS):
        signals.append(Signal("impersonation", 20, "The message claims to be an official support/account team — a common impersonation tactic."))

    if _find_matches(text_lower, JOB_INVESTMENT_SCAM_PATTERNS):
        signals.append(Signal("job_investment_scam", 15, "The message resembles a suspicious job or investment offer promising unrealistic returns."))

    if _find_matches(text_lower, ROMANCE_FINANCIAL_SCAM_PATTERNS):
        signals.append(Signal("romance_financial_scam", 15, "The message contains patterns associated with romance or emergency-money scams."))

    if _find_matches(text_lower, CLICK_PATTERNS):
        signals.append(Signal("click_pressure", 10, "The message pressures you to click a link immediately."))

    detected_urls = extract_urls(text)
    if detected_urls:
        signals.append(Signal("contains_url", 5, f"The message contains {len(detected_urls)} link(s), which were analyzed separately."))
        for u in detected_urls[:3]:  # cap to avoid runaway scoring on spammy text
            url_signals, _ = analyze_url(u)
            # Fold in a portion of URL risk, capped, to avoid double-dominating the score
            url_points = min(25, sum(s.points for s in url_signals) // 2)
            if url_points > 0:
                signals.append(Signal("linked_url_risk", url_points, f"A link in the message ({u}) shows phishing-related indicators."))

    return signals, detected_urls
