
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from security.jwt import get_current_user


def require_role(allowed_roles: list[str]):
    def role_checker(
        current_email: str = Depends(get_current_user),
        db: Session = Depends(get_db)
    ):
        user = db.query(User).filter(
            User.email == current_email
        ).first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource"
            )

        return user

    return role_checker
