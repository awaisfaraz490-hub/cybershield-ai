"""
CyberShield AI — FastAPI application entrypoint.

Defensive cybersecurity education tool: analyzes links, messages, and
screenshots for common phishing/scam indicators. Does not perform any
credential collection, hacking, or unauthorized access.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings, BASE_DIR
from app.database import init_db
from app.routers import auth, scan, pages, tips

logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cybershield")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- startup ---
    try:
        init_db()
        logger.info("Database initialized successfully.")
    except Exception as exc:
        logger.error("Database initialization failed: %s", exc)
        raise

    if not settings.OPENAI_API_KEY:
        logger.info("OPENAI_API_KEY not set — running with local heuristic analysis only.")

    from app.services.ocr_service import is_ocr_available
    if not is_ocr_available():
        logger.warning("OCR is not available — screenshot text extraction will be disabled gracefully.")

    yield
    # --- shutdown --- (nothing to clean up currently)


app = FastAPI(
    title=settings.APP_NAME,
    description="Detect suspicious links, messages and screenshots before they put your account at risk.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — restricted to configured origins only
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))


# ---------------------------------------------------------------------------
# Global exception handling — never leak stack traces to users
# ---------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = [
        {"field": ".".join(str(p) for p in e["loc"][1:]), "message": e["msg"]}
        for e in exc.errors()
    ]
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={"detail": "Validation error.", "errors": errors})
    return templates.TemplateResponse("error.html", {"request": request, "user": None, "app_name": settings.APP_NAME, "message": "Please check your input and try again."}, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    if exc.status_code == 404:
        return templates.TemplateResponse("404.html", {"request": request, "user": None, "app_name": settings.APP_NAME}, status_code=404)
    return templates.TemplateResponse("error.html", {"request": request, "user": None, "app_name": settings.APP_NAME, "message": str(exc.detail)}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled server error on %s", request.url.path)
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=500, content={"detail": "An unexpected error occurred. Please try again."})
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "user": None, "app_name": settings.APP_NAME, "message": "Something went wrong on our end. Please try again."},
        status_code=500,
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(scan.scans_router)
app.include_router(tips.router)
app.include_router(pages.router)
