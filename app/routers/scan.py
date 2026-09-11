"""Scan routes: URL scanner, message scanner, image scanner, history."""
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.scan import Scan
from app.schemas.scan import UrlScanRequest, MessageScanRequest, ScanResult, ScanHistoryItem
from app.routers.deps import get_current_user
from app.services.url_analyzer import analyze_url
from app.services.message_analyzer import analyze_message, extract_urls
from app.services.scoring import ScoringEngine
from app.services.recommendations import build_explanation, build_recommended_actions
from app.services.ocr_service import extract_text_from_image, is_ocr_available, OCRUnavailableError
from app.config import settings

logger = logging.getLogger("cybershield.scan")

router = APIRouter(prefix="/api/scan", tags=["scan"])


def _save_scan(db: Session, user: User, scan_type: str, input_summary: str, result) -> Scan:
    scan = Scan(
        user_id=user.id,
        scan_type=scan_type,
        input_summary=input_summary[:280],
        risk_score=result.score,
        risk_level=result.level,
        findings=json.dumps(result.findings),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/url", response_model=ScanResult)
def scan_url(payload: UrlScanRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    signals, _meta = analyze_url(payload.url)
    result = ScoringEngine.compute(signals)

    _save_scan(db, user, "url", payload.url, result)

    return ScanResult(
        scan_type="url",
        risk_score=result.score,
        risk_level=result.level,
        findings=result.findings,
        recommended_actions=build_recommended_actions(result),
        explanation=build_explanation(result),
        detected_urls=[payload.url],
        analysis_note="Local heuristic analysis — external reputation verification is not configured.",
    )


@router.post("/message", response_model=ScanResult)
def scan_message(payload: MessageScanRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    signals, urls = analyze_message(payload.message)
    result = ScoringEngine.compute(signals)

    _save_scan(db, user, "message", payload.message, result)

    return ScanResult(
        scan_type="message",
        risk_score=result.score,
        risk_level=result.level,
        findings=result.findings,
        recommended_actions=build_recommended_actions(result),
        explanation=build_explanation(result),
        detected_urls=urls,
        analysis_note="Local heuristic analysis based on common phishing/scam language patterns.",
    )


@router.post("/image", response_model=ScanResult)
async def scan_image(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if file.content_type not in settings.ALLOWED_IMAGE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported file type. Please upload a JPG, JPEG, PNG, or WebP image.",
        )

    contents = await file.read()
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(contents) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Image is too large. Maximum size is {settings.MAX_UPLOAD_SIZE_MB}MB.",
        )
    if len(contents) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The uploaded file is empty.")

    if not is_ocr_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OCR is not available on this server. Please paste the message text into the Message Scanner instead.",
        )

    try:
        extracted_text = extract_text_from_image(contents)
    except OCRUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))

    if not extracted_text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No readable text was found in this image. Try a clearer screenshot or paste the message manually.",
        )

    signals, urls = analyze_message(extracted_text)
    result = ScoringEngine.compute(signals)

    _save_scan(db, user, "image", f"[screenshot] {extracted_text[:200]}", result)

    # Per privacy requirements, the raw image bytes are never written to disk
    # unless PERSIST_UPLOADED_IMAGES is explicitly enabled.
    if settings.PERSIST_UPLOADED_IMAGES:
        safe_name = f"user_{user.id}_{file.filename}".replace("/", "_").replace("\\", "_")
        with open(settings.UPLOAD_DIR / safe_name, "wb") as f:
            f.write(contents)

    return ScanResult(
        scan_type="image",
        risk_score=result.score,
        risk_level=result.level,
        findings=result.findings,
        recommended_actions=build_recommended_actions(result),
        explanation=build_explanation(result),
        extracted_text=extracted_text,
        detected_urls=urls,
        analysis_note="Text extracted via OCR and analyzed using local heuristic pattern detection.",
    )


@router.get("/history", response_model=list[ScanHistoryItem])
def get_history(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scans = (
        db.query(Scan)
        .filter(Scan.user_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(100)
        .all()
    )
    return scans


# ---------------------------------------------------------------------------
# /api/scans — matches the REST spec (list + detail) alongside /api/scan/*
# ---------------------------------------------------------------------------
scans_router = APIRouter(prefix="/api/scans", tags=["scans"])


@scans_router.get("", response_model=list[ScanHistoryItem])
def list_scans(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return (
        db.query(Scan)
        .filter(Scan.user_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(100)
        .all()
    )


@scans_router.get("/{scan_id}", response_model=ScanHistoryItem)
def get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan
