from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.sql import func
from app.database import Base


class MaliciousSite(Base):
    __tablename__ = "malicious_sites"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False)
    domain = Column(String, nullable=False, index=True)
    # confirmed_phishing | suspicious | malware | user_reported
    category = Column(String, nullable=False)
    # api_detection | auto_detected | user_reported
    source = Column(String, nullable=False)
    threat_types = Column(JSON, default=list)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    confirmed_at = Column(DateTime(timezone=True), nullable=True)
