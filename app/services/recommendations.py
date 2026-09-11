"""
Generates human-friendly explanations and recommended actions based on
the scoring result. Kept separate from the scoring engine so wording can
be refined independently of the point system.
"""
from app.services.scoring import ScoreResult

DEFAULT_ACTIONS = [
    "Verify the sender through an official, independently-found channel (not a link/number from this message).",
    "Do not enter your password, OTP, or any personal/financial information.",
    "Avoid clicking the link directly — visit the official website or app instead.",
    "Report and/or block the sender if this looks like spam or a scam.",
]

LOW_RISK_ACTIONS = [
    "No strong phishing indicators were detected, but always stay cautious with unexpected messages.",
    "Still avoid sharing passwords, OTPs, or payment details with anyone who messages you first.",
]


def build_explanation(result: ScoreResult) -> str:
    if not result.signals:
        return (
            "No strong phishing or scam indicators were detected in this content. "
            "This is not a guarantee of safety — always stay cautious."
        )
    lead = {
        "Low Risk": "This content shows minimal indicators of phishing or scam activity.",
        "Moderate Risk": "This content shows some indicators commonly seen in phishing or scam attempts.",
        "High Risk": "This content shows multiple indicators commonly associated with phishing or social engineering.",
        "Critical Risk": "This content shows strong, multiple indicators of a likely phishing or scam attempt.",
    }.get(result.level, "This content was analyzed for common phishing and scam indicators.")
    return lead


def build_recommended_actions(result: ScoreResult) -> list[str]:
    if result.level == "Low Risk":
        return LOW_RISK_ACTIONS
    actions = list(DEFAULT_ACTIONS)
    if any(s.name in ("otp_request",) for s in result.signals):
        actions.insert(0, "Never share an OTP with anyone, even someone claiming to be official support.")
    if any(s.name in ("credential_request",) for s in result.signals):
        actions.insert(0, "Do not provide your password on this page or any linked page.")
    if any(s.name in ("suspicious_payment_request",) for s in result.signals):
        actions.insert(0, "Do not send money, gift cards, or payment details based on this message.")
    return actions
