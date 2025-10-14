"""
Authentication and authorization module for SecureDocs.
Handles JWT-based authentication, password hashing, and RBAC middleware.
"""
import os
import re
import bcrypt
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional
from app.models import User, UserRole
from app.utils import get_db


JWT_SECRET = os.getenv("JWT_SECRET", "your_secret_key")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
REFRESH_TOKEN_DAYS = 7

security = HTTPBearer()


def validate_username(username: str) -> None:
    """
    Validate username requirements.
    
    Requirements:
    - Only alphanumeric characters (letters and numbers)
    - Must not start with a numeric digit
    - Minimum 3 characters
    
    Raises HTTPException if username doesn't meet requirements.
    """
    if len(username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username must be at least 3 characters long"
        )
    
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9]*$', username):
        raise HTTPException(
            status_code=400,
            detail="Username must start with a letter and contain only letters and numbers"
        )


def validate_password_strength(password: str) -> None:
    
    if len(password) < 8:
        raise HTTPException(
            status_code=400, 
            detail="Password must be at least 8 characters long"
        )
    
    if not re.search(r'[A-Z]', password):
        raise HTTPException(
            status_code=400, 
            detail="Password must contain at least one uppercase letter"
        )
    
    if not re.search(r'[0-9]', password):
        raise HTTPException(
            status_code=400, 
            detail="Password must contain at least one numeric digit"
        )


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    return password_hash.decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))


def create_access_token(user_id: int, username: str, role: UserRole) -> str:
    """Create a JWT access token for authenticated user."""
    expiration = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role.value,
        "exp": expiration,
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def create_refresh_token(user_id: int) -> str:
    """Create a JWT refresh token for token renewal."""
    expiration = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_DAYS)
    payload = {
        "user_id": user_id,
        "exp": expiration,
        "iat": datetime.utcnow(),
        "type": "refresh"
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)) -> User:
    """
    Dependency function to get current authenticated user from JWT token.
    Validates token and retrieves user from database.
    """
    token = credentials.credentials
    payload = decode_token(token)
    
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user


def require_permission(permission: str):
    """
    RBAC middleware decorator to check user permissions.
    Validates that the current user has the required permission.
    """
    def permission_checker(user: User = Depends(get_current_user)) -> User:
        if not user.has_permission(permission):
            raise HTTPException(
                status_code=403, 
                detail=f"Access denied. Required permission: {permission}"
            )
        return user
    return permission_checker


def register_user(db: Session, username: str, password: str, role: UserRole = UserRole.USER) -> User:
    """Register a new user with username and password validation."""
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Validate username
    validate_username(username)
    
    # Validate password strength
    validate_password_strength(password)
    
    password_hash = hash_password(password)
    new_user = User(
        username=username,
        password_hash=password_hash,
        role=role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate user credentials and return user if valid."""
    # Validate password format before attempting authentication
    try:
        validate_password_strength(password)
    except HTTPException:
        # If password doesn't meet strength requirements, authentication fails
        return None
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    
    if not verify_password(password, user.password_hash):
        return None
    
    return user


def get_client_ip(request: Request) -> str:
    """Extract client IP address from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
