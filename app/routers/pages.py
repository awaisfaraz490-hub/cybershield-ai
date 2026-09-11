"""HTML page routes (server-rendered via Jinja2 templates)."""
import json
from fastapi import APIRouter, Request, Depends
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app.models.scan import Scan
from app.routers.deps import get_current_user_optional
from app.routers.tips import SECURITY_TIPS

from app.config import BASE_DIR

router = APIRouter(tags=["pages"])
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))


def base_context(request: Request, user, **extra):
    ctx = {"request": request, "user": user, "app_name": settings.APP_NAME, "app_tagline": settings.APP_TAGLINE}
    ctx.update(extra)
    return ctx


@router.get("/")
def landing_page(request: Request, user=Depends(get_current_user_optional)):
    return templates.TemplateResponse("index.html", base_context(request, user))


@router.get("/register")
def register_page(request: Request, user=Depends(get_current_user_optional)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("register.html", base_context(request, user))


@router.get("/login")
def login_page(request: Request, user=Depends(get_current_user_optional)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse("login.html", base_context(request, user))


@router.get("/logout")
def logout_page():
    resp = RedirectResponse(url="/", status_code=302)
    resp.delete_cookie(settings.SESSION_COOKIE_NAME)
    return resp


@router.get("/dashboard")
def dashboard_page(request: Request, user=Depends(get_current_user_optional), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.created_at.desc()).limit(10).all()
    total = db.query(Scan).filter(Scan.user_id == user.id).count()
    high = db.query(Scan).filter(Scan.user_id == user.id, Scan.risk_level.in_(["High Risk", "Critical Risk"])).count()
    medium = db.query(Scan).filter(Scan.user_id == user.id, Scan.risk_level == "Moderate Risk").count()
    low = db.query(Scan).filter(Scan.user_id == user.id, Scan.risk_level == "Low Risk").count()

    return templates.TemplateResponse(
        "dashboard.html",
        base_context(request, user, scans=scans, total=total, high=high, medium=medium, low=low),
    )


@router.get("/scan/url")
def scan_url_page(request: Request, user=Depends(get_current_user_optional)):
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("scan_url.html", base_context(request, user))


@router.get("/scan/message")
def scan_message_page(request: Request, user=Depends(get_current_user_optional)):
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("scan_message.html", base_context(request, user))


@router.get("/scan/image")
def scan_image_page(request: Request, user=Depends(get_current_user_optional)):
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("scan_image.html", base_context(request, user))


@router.get("/history")
def history_page(request: Request, user=Depends(get_current_user_optional), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.created_at.desc()).limit(100).all()
    return templates.TemplateResponse("history.html", base_context(request, user, scans=scans))


@router.get("/history/{scan_id}")
def history_detail_page(scan_id: int, request: Request, user=Depends(get_current_user_optional), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    findings = json.loads(scan.findings) if scan else []
    return templates.TemplateResponse("result.html", base_context(request, user, scan=scan, findings=findings))


@router.get("/tips")
def tips_page(request: Request, user=Depends(get_current_user_optional)):
    return templates.TemplateResponse("tips.html", base_context(request, user, tips=SECURITY_TIPS))


@router.get("/profile")
def profile_page(request: Request, user=Depends(get_current_user_optional)):
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("profile.html", base_context(request, user))


@router.get("/privacy")
def privacy_page(request: Request, user=Depends(get_current_user_optional)):
    return templates.TemplateResponse("privacy.html", base_context(request, user))
