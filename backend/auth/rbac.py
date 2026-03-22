from fastapi import Depends, HTTPException, status
from backend.auth.dependencies import get_current_user


def require_role(role: str):
    """
    Dependency that checks the current user has the required role.
    Usage: Depends(require_role("admin")) or Depends(require_role("user"))

    Fix: added null check on user.role before accessing user.role.name
    Previously this crashed with AttributeError when role_id was None.
    """
    def role_checker(user=Depends(get_current_user)):

        if user.role is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account has no role assigned. Contact the admin."
            )

        if user.role.name.lower() != role.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {role}"
            )

        return user

    return role_checker


def require_any_role():
    """
    Dependency that just requires the user to be logged in.
    Any role is accepted — used for scan endpoints.
    """
    def role_checker(user=Depends(get_current_user)):

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )

        return user

    return role_checker