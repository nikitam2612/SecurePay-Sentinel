
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TransactionCreate(BaseModel):
    amount: Decimal = Field(gt=0, max_digits=10, decimal_places=2)
    currency: str = Field(default="INR", min_length=3, max_length=3)
    description: str | None = Field(default=None, max_length=255)


class TransactionResponse(BaseModel):
    id: int
    user_id: int
    amount: Decimal
    currency: str
    status: str
    description: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AuditLogResponse(BaseModel):
    id: int
    user_id: int | None
    action: str
    details: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
class EncryptedDataCreate(BaseModel):
    content: str = Field(
        min_length=1,
        max_length=1000
    )


class EncryptedDataResponse(BaseModel):
    id: int
    user_id: int
    content: str
    created_at: datetime
