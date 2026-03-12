from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import User
from backend.config import settings

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):

    try:
        # Decode JWT
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )

        # TEMP DEBUG
        print("=== JWT TOKEN RECEIVED ===")
        print("RAW TOKEN:", token)
        print("DECODED PAYLOAD:", payload)

        username = payload.get("sub")

        if username is None:
            print("ERROR: 'sub' field missing in token payload")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )

    except Exception as e:
        print("JWT DECODE ERROR:", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )

    # Query user
    user = db.query(User).filter(User.username == username).first()

    # TEMP DEBUG
    print("=== USER LOOKUP ===")
    print("USERNAME FROM TOKEN:", username)
    print("USER FOUND IN DB:", user)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    return user