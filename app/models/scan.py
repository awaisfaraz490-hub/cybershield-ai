"""Scan model — stores a safe summary of each analysis, never raw secrets."""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_type = Column(String(20), nullable=False)  # url | message | image
    input_summary = Column(String(300), nullable=False)  # truncated, safe summary only
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(20), nullable=False)
    findings = Column(Text, nullable=False)  # JSON-encoded list of indicator strings
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="scans")
