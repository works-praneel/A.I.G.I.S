from backend.database.database import SessionLocal, engine, Base
from backend.database.models import User
from backend.auth.password import hash_password

def init_root_user():
    # Ensure tables exist
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        root_email = "subhaprakashjana@gmail.com"
        # Check if root already exists
        root_user = db.query(User).filter(User.email == root_email).first()
        
        if not root_user:
            print(f"Creating permanent Root user: {root_email}")
            new_root = User(
                email=root_email,
                hashed_password=hash_password("Subh@2116"),
                role="root",
                permissions=["file_scan", "link_scan", "github_scan", "admin_panel"]
            )
            db.add(new_root)
            db.commit()
        else:
            # Optional: Always update the password to ensure it matches your request
            root_user.hashed_password = hash_password("Subh@2116")
            root_user.role = "root"
            db.commit()
            print("Root user credentials verified and updated.")
    finally:
        db.close()

if __name__ == "__main__":
    init_root_user()