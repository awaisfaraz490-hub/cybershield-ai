"""
Optional OCR service using pytesseract + Pillow.

Gracefully degrades if pytesseract/tesseract binary is not installed —
the rest of the application must keep working (users can paste text
manually instead).
"""
import io
import logging

logger = logging.getLogger("cybershield.ocr")

_OCR_AVAILABLE = True
try:
    import pytesseract
    from PIL import Image
except ImportError:
    _OCR_AVAILABLE = False


class OCRUnavailableError(Exception):
    """Raised when OCR dependencies or the tesseract binary are unavailable."""


def is_ocr_available() -> bool:
    if not _OCR_AVAILABLE:
        return False
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def extract_text_from_image(image_bytes: bytes) -> str:
    """
    Extract visible text from an image using OCR.
    Raises OCRUnavailableError if OCR cannot run for any reason.
    """
    if not _OCR_AVAILABLE:
        raise OCRUnavailableError("OCR dependencies (pytesseract/Pillow) are not installed.")

    try:
        image = Image.open(io.BytesIO(image_bytes))
        image = image.convert("RGB")
        text = pytesseract.image_to_string(image)
        return text.strip()
    except pytesseract.TesseractNotFoundError as exc:
        logger.warning("Tesseract binary not found: %s", exc)
        raise OCRUnavailableError("The Tesseract OCR engine is not installed on this system.") from exc
    except Exception as exc:
        logger.warning("OCR extraction failed: %s", exc)
        raise OCRUnavailableError("Could not extract text from this image.") from exc
