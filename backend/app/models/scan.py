from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from app.database import Base


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    url = Column(String, nullable=False)
    domain = Column(String, nullable=False, index=True)
    verdict = Column(String, nullable=False)       # safe | suspicious | dangerous
    risk_score = Column(Integer, default=0)
    threat_types = Column(JSON, default=list)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
