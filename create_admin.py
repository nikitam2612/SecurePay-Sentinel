
from getpass import getpass

from app.database import SessionLocal
from app.models import User
from security.password import hash_password

db = SessionLocal()

admin_email = input("Enter admin email: ").strip()
admin_password = getpass("Enter admin password: ")

try:
    if len(admin_password) < 8:
        raise ValueError("Password must contain at least 8 characters.")

    existing_user = db.query(User).filter(
        User.email == admin_email
    ).first()

    if existing_user:
        print("This account already exists.")
    else:
        admin = User(
            name="Admin User",
            email=admin_email,
            hashed_password=hash_password(admin_password),
            role="admin"
        )

        db.add(admin)
        db.commit()

        print("Admin account created successfully!")

except Exception as error:
    db.rollback()
    print("Error:", error)

finally:
    db.close()
