from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    # Truncate to 72 bytes to prevent Bcrypt ValueError
    return pwd_context.hash(password[:72])

def verify_password(plain_password, hashed_password):
    # Truncate here as well so the comparison works
    return pwd_context.verify(plain_password[:72], hashed_password)