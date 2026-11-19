from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import engine, get_db
from app import models, schemas

from security.password import hash_password, verify_password
from security.encryption import encrypt_data, decrypt_data
from security.jwt import create_access_token, get_current_user
from security.permissions import require_role
from security.audit import log_event
from security.security_headers import security_headers_middleware

from security.rate_limit import (
    check_login_rate_limit,
    record_failed_login,
    reset_login_attempts,
    check_transaction_rate_limit
)


models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SecurePay Sentinel",
    description="Secure Payment API and Vulnerability Assessment Platform",
    version="0.1.0"
)
app.middleware("http")(security_headers_middleware)

@app.get("/")
def home():
    return {
        "message": "Welcome to SecurePay Sentinel",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/health/database")
def database_health():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return {
            "status": "healthy",
            "database": "connected",
            "engine": "SQLite"
        }

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable"
        ) from exc


@app.post(
    "/auth/register",
    response_model=schemas.UserResponse,
    status_code=status.HTTP_201_CREATED
)
def register_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db)
):
    existing_user = db.query(models.User).filter(
        models.User.email == user.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    new_user = models.User(
        name=user.name,
        email=user.email,
        hashed_password=hash_password(user.password),
        role="customer"
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        log_event(
            db=db,
            action="USER_REGISTERED",
            user_id=new_user.id,
            details="New customer account registered"
        )

        return new_user

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="User registration failed"
        ) from exc


@app.post(
    "/auth/login",
    response_model=schemas.TokenResponse
)
def login_user(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "unknown"

    check_login_rate_limit(client_ip)

    existing_user = db.query(models.User).filter(
        models.User.email == form_data.username
    ).first()

    if not existing_user or not verify_password(
        form_data.password,
        existing_user.hashed_password
    ):
        record_failed_login(client_ip)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        reset_login_attempts(client_ip)

        log_event(
            db=db,
            action="USER_LOGIN",
            user_id=existing_user.id,
            details="User logged in successfully"
        )

        access_token = create_access_token(
            data={"sub": existing_user.email}
        )

        return {
            "access_token": access_token,
            "token_type": "bearer"
        }

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Login processing failed"
        ) from exc

@app.get(
    "/auth/me",
    response_model=schemas.UserResponse
)
def get_my_profile(
    current_email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(
        models.User.email == current_email
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User account not found"
        )

    return user


@app.get("/admin/dashboard")
def admin_dashboard(
    current_user: models.User = Depends(require_role(["admin"]))
):
    return {
        "message": "Welcome to the Admin Dashboard",
        "user": current_user.name,
        "role": current_user.role
    }



@app.post(
    "/transactions",
    response_model=schemas.TransactionResponse,
    status_code=status.HTTP_201_CREATED
)
def create_transaction(
    transaction: schemas.TransactionCreate,
    current_email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(
        models.User.email == current_email
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    # Check transaction API rate limit
    check_transaction_rate_limit(user.id)

    new_transaction = models.Transaction(
        user_id=user.id,
        amount=transaction.amount,
        currency=transaction.currency.upper(),
        description=transaction.description,
        status="pending"
    )

    try:
        db.add(new_transaction)
        db.commit()
        db.refresh(new_transaction)

        log_event(
            db=db,
            action="TRANSACTION_CREATED",
            user_id=user.id,
            details=(
                f"Transaction ID: {new_transaction.id}, "
                f"Amount: {new_transaction.amount} "
                f"{new_transaction.currency}"
            )
        )

        return new_transaction

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Transaction creation failed"
        ) from exc


@app.get(
    "/transactions/my",
    response_model=list[schemas.TransactionResponse]
)
def get_my_transactions(
    current_email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(
        models.User.email == current_email
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    transactions = db.query(models.Transaction).filter(
        models.Transaction.user_id == user.id
    ).order_by(
        models.Transaction.created_at.desc()
    ).all()

    return transactions


@app.get(
    "/admin/transactions",
    response_model=list[schemas.TransactionResponse]
)
def get_all_transactions(
    current_user: models.User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    transactions = db.query(models.Transaction).order_by(
        models.Transaction.created_at.desc()
    ).all()

    return transactions

@app.get(
    "/admin/audit-logs",
    response_model=list[schemas.AuditLogResponse]
)
def get_audit_logs(
    current_user: models.User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    audit_logs = db.query(models.AuditLog).order_by(
        models.AuditLog.created_at.desc()
    ).all()

    return audit_logs


@app.post(
    "/encrypted-data",
    response_model=schemas.EncryptedDataResponse,
    status_code=status.HTTP_201_CREATED
)
def store_encrypted_data(
    data: schemas.EncryptedDataCreate,
    current_email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(
        models.User.email == current_email
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    encrypted_content = encrypt_data(data.content)

    new_record = models.EncryptedData(
        user_id=user.id,
        encrypted_content=encrypted_content
    )

    try:
        db.add(new_record)
        db.commit()
        db.refresh(new_record)

        return {
            "id": new_record.id,
            "user_id": new_record.user_id,
            "content": data.content,
            "created_at": new_record.created_at
        }

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Encrypted data storage failed"
        ) from exc


@app.get(
    "/encrypted-data/my",
    response_model=list[schemas.EncryptedDataResponse]
)
def get_my_encrypted_data(
    current_email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(
        models.User.email == current_email
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    records = db.query(models.EncryptedData).filter(
        models.EncryptedData.user_id == user.id
    ).order_by(
        models.EncryptedData.created_at.desc()
    ).all()

    return [
        {
            "id": record.id,
            "user_id": record.user_id,
            "content": decrypt_data(record.encrypted_content),
            "created_at": record.created_at
        }
        for record in records
    ]
