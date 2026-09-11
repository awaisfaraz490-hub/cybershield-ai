"""Security tips API."""
from fastapi import APIRouter

router = APIRouter(prefix="/api", tags=["tips"])

SECURITY_TIPS = [
    {"title": "Never share OTPs", "detail": "No legitimate service will ever ask you to share a one-time password with them."},
    {"title": "Never share passwords", "detail": "Official support teams never need your account password to help you."},
    {"title": "Don't trust urgency", "detail": "Scammers create time pressure to stop you from thinking carefully. Pause before acting."},
    {"title": "Verify links before clicking", "detail": "Hover over or long-press a link to preview its real destination first."},
    {"title": "Use official apps and websites", "detail": "Navigate directly to the app or site instead of clicking a link in a message."},
    {"title": "Enable two-factor authentication", "detail": "2FA adds a strong extra layer of protection even if your password leaks."},
    {"title": "Keep apps updated", "detail": "Updates often patch security vulnerabilities that attackers exploit."},
    {"title": "Be careful with attachments", "detail": "Unexpected attachments, even from known contacts, can carry malware."},
    {"title": "Don't trust fake support accounts", "detail": "Real companies rarely message you first on WhatsApp or social media."},
    {"title": "Verify prizes and financial offers independently", "detail": "Search for the offer separately, or contact the company through official channels."},
]


@router.get("/security-tips")
def get_security_tips():
    return {"tips": SECURITY_TIPS}
