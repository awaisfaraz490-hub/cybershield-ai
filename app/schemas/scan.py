"""Pydantic schemas for scan requests/responses."""
from datetime import datetime
from pydantic import BaseModel, field_validator


class UrlScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Please provide a URL to scan.")
        if len(v) > 2048:
            raise ValueError("URL is too long.")
        return v


class MessageScanRequest(BaseModel):
    message: str

    @field_validator("message")
    @classmethod
    def not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Please provide a message to analyze.")
        if len(v) > 8000:
            raise ValueError("Message is too long (max 8000 characters).")
        return v


class ScanResult(BaseModel):
    scan_type: str
    risk_score: int
    risk_level: str
    findings: list[str]
    recommended_actions: list[str]
    explanation: str
    extracted_text: str | None = None
    detected_urls: list[str] = []
    analysis_note: str

    class Config:
        from_attributes = True


class ScanHistoryItem(BaseModel):
    id: int
    scan_type: str
    input_summary: str
    risk_score: int
    risk_level: str
    created_at: datetime

    class Config:
        from_attributes = True
