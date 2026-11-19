
from sqlalchemy.orm import Session

from app.models import AuditLog


def log_event(
    db: Session,
    action: str,
    user_id: int | None = None,
    details: str | None = None
):
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        details=details
    )

    db.add(audit_log)
    db.commit()
