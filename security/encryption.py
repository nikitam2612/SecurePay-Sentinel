
import os

from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY is missing from .env")

fernet = Fernet(ENCRYPTION_KEY.encode())


def encrypt_data(data: str) -> str:
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()


def decrypt_data(encrypted_data: str) -> str:
    decrypted_data = fernet.decrypt(encrypted_data.encode())
    return decrypted_data.decode()
