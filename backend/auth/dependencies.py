from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import User
from backend.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Extract and validate the JWT token from the request header.
    Returns the User object for the authenticated user.

    Fix: token is created with "sub": str(user.id)
    so we query by ID not by username.
    Previously this queried User.username == sub which always
    returned None because sub contains the numeric ID string.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )

        # sub contains str(user.id) — cast back to int for the query
        user_id: str = payload.get("sub")

        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    # Query by ID not by username
    user = db.query(User).filter(User.id == int(user_id)).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    return user


def get_current_user_optional(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Same as get_current_user but returns None instead of
    raising an exception. Used for endpoints that work both
    authenticated and unauthenticated.
    """
    try:
        return get_current_user(token=token, db=db)
    except HTTPException:
        return None