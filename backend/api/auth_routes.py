from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.schemas import UserCreate
from backend.database.models import User, Role
from backend.auth.password import hash_password, verify_password
from backend.auth.jwt_handler import create_access_token
from backend.auth.dependencies import get_current_user

router = APIRouter(tags=["auth"])


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user account.

    Role assignment:
    - If no users exist yet → this user becomes Admin
    - All subsequent users get the "user" role automatically
    This means the very first person to register owns the system.
    """

    existing = db.query(User).filter(
        User.username == data.username
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Ensure roles exist — create them if this is a fresh install
    _seed_roles(db)

    # First user ever → Admin, everyone else → user role
    user_count = db.query(User).count()
    role_name = "admin" if user_count == 0 else "user"
    role = db.query(Role).filter(Role.name == role_name).first()

    new_user = User(
        username=data.username,
        password_hash=hash_password(data.password),
        role_id=role.id if role else None
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User created successfully",
        "username": new_user.username,
        "role": role_name
    }


@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Login with username and password.
    Returns a JWT bearer token.
    """

    user = db.query(User).filter(
        User.username == form_data.username
    ).first()

    if not user or not verify_password(
        form_data.password, user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": user.role.name if user.role else "none"
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role.name if user.role else "none"
    }


@router.get("/me")
def get_me(current_user=Depends(get_current_user)):
    """
    Returns the currently authenticated user's profile.
    """
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role.name if current_user.role else "none",
        "created_at": current_user.created_at
    }


def _seed_roles(db: Session):
    """
    Ensure admin and user roles exist in the DB.
    Called on every register — safe to call multiple times
    because it only inserts if the role doesn't exist.
    """
    for role_name in ["admin", "user"]:
        exists = db.query(Role).filter(
            Role.name == role_name
        ).first()
        if not exists:
            db.add(Role(name=role_name))
    db.commit()