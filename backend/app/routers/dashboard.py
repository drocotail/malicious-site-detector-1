from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.jwt_handler import get_current_user
from app.database import get_db
from app.models.malicious_site import MaliciousSite
from app.models.scan import ScanHistory
from app.models.user import User

router = APIRouter()


@router.get("/history")
def scan_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    records = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": r.id,
            "url": r.url,
            "domain": r.domain,
            "verdict": r.verdict,
            "risk_score": r.risk_score,
            "threat_types": r.threat_types,
            "scanned_at": r.created_at.isoformat(),
        }
        for r in records
    ]


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    total = db.query(ScanHistory).count()
    dangerous = db.query(ScanHistory).filter(ScanHistory.verdict == "dangerous").count()
    suspicious = db.query(ScanHistory).filter(ScanHistory.verdict == "suspicious").count()
    db_entries = db.query(MaliciousSite).count()

    return {
        "total_scans": total,
        "dangerous_detected": dangerous,
        "suspicious_detected": suspicious,
        "db_entries": db_entries,
    }
