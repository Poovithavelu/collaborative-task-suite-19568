from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional, List, Dict

import os
from fastapi import APIRouter, Depends, HTTPException, status, Header

from pydantic import BaseModel, EmailStr, Field, constr
from jose import JWTError, jwt
from passlib.context import CryptContext

# In a production setup, replace these in-memory stores with actual Postgres-access logic.
# This is a minimal scaffold that respects interfaces and enables wiring and documentation.
# The actual DB layer should use env vars to connect to Supabase Postgres (see .env.example).
_fake_users_db: Dict[str, Dict] = {}
_fake_orgs_db: Dict[str, Dict] = {}
_fake_memberships: List[Dict] = []  # items: {user_id, org_id, role}
# Token blacklist or store can be implemented if needed for revocation; not required for stateless JWT.

router = APIRouter(prefix="/auth", tags=["Authentication"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ENV configuration (MUST be provided via .env)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-env")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))

# PUBLIC_INTERFACE
class Token(BaseModel):
    """Token response payload for successful authentication."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Type of the token (usually 'bearer')")
    expires_in: int = Field(..., description="Token expiry time in seconds")
    org: Optional[dict] = Field(None, description="Current organization context for the session")

# PUBLIC_INTERFACE
class RegisterRequest(BaseModel):
    """Registration request with email, password and optional organization name."""
    email: EmailStr = Field(..., description="User email address")
    password: constr(min_length=8) = Field(..., description="Strong password with at least 8 characters")
    full_name: Optional[constr(min_length=1)] = Field(None, description="Full name for the user profile")
    org_name: Optional[constr(min_length=1)] = Field(None, description="Organization name to create/join on signup")

# PUBLIC_INTERFACE
class LoginRequest(BaseModel):
    """Email-password login payload."""
    email: EmailStr = Field(..., description="User email address")
    password: constr(min_length=8) = Field(..., description="Password for authentication")

# PUBLIC_INTERFACE
class UserResponse(BaseModel):
    """Response payload carrying user information and current org context."""
    id: str = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email")
    full_name: Optional[str] = Field(None, description="Full name")
    current_org: Optional[dict] = Field(None, description="Current organization context")

# PUBLIC_INTERFACE
class SwitchOrgRequest(BaseModel):
    """Request payload for switching current organization context for the session."""
    org_id: str = Field(..., description="Target organization ID to switch to")

# Utility functions
def _verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def _hash_password(password: str) -> str:
    return pwd_context.hash(password)

def _create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=JWT_EXPIRES_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def _get_user_by_email(email: str) -> Optional[Dict]:
    return _fake_users_db.get(email.lower())

def _get_org(org_id: str) -> Optional[Dict]:
    return _fake_orgs_db.get(org_id)

def _list_user_orgs(user_id: str) -> List[Dict]:
    org_ids = [m["org_id"] for m in _fake_memberships if m["user_id"] == user_id]
    return [_fake_orgs_db[oid] for oid in org_ids if oid in _fake_orgs_db]

def _user_has_membership(user_id: str, org_id: str) -> bool:
    return any(m for m in _fake_memberships if m["user_id"] == user_id and m["org_id"] == org_id)

# Dependency to get current user from Authorization header
async def _get_current_user(authorization: Annotated[Optional[str], Header(None)]):
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
    try:
        scheme, token = authorization.split(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth scheme")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Authorization header")
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")
        email = payload.get("email")
        current_org_id = payload.get("org_id")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token decode error")

    user = None
    if email:
        user = _get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    # Ensure RLS/org-awareness-like behavior: current org must be in memberships
    org = _get_org(current_org_id) if current_org_id else None
    if org and not _user_has_membership(user["id"], org["id"]):
        # If token claims an org the user is not a member of, forbid.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No membership for org in token")
    return {"user": user, "org": org, "raw_token": token, "claims": payload}

# PUBLIC_INTERFACE
@router.post("/register", response_model=UserResponse, status_code=201, summary="Register user", description="Create a new user, hash password, and optionally create/join an organization.")
async def register(payload: RegisterRequest) -> UserResponse:
    """Register a new user into the system and optionally create or join an organization.

    Parameters:
    - payload: RegisterRequest containing email, password, full_name, and optional org_name.

    Returns:
    - UserResponse with user info and possibly the created org as current context.
    """
    email_key = payload.email.lower()
    if _get_user_by_email(email_key):
        raise HTTPException(status_code=409, detail="User already exists")

    new_user_id = f"user_{len(_fake_users_db)+1}"
    hashed = _hash_password(payload.password)
    user_doc = {
        "id": new_user_id,
        "email": email_key,
        "full_name": payload.full_name,
        "password_hash": hashed,
    }
    _fake_users_db[email_key] = user_doc

    current_org = None
    if payload.org_name:
        org_id = f"org_{len(_fake_orgs_db)+1}"
        org_doc = {
            "id": org_id,
            "name": payload.org_name,
            "created_by": new_user_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _fake_orgs_db[org_id] = org_doc
        _fake_memberships.append({"user_id": new_user_id, "org_id": org_id, "role": "owner"})
        current_org = org_doc

    return UserResponse(
        id=new_user_id,
        email=email_key,
        full_name=payload.full_name,
        current_org=current_org,
    )

# PUBLIC_INTERFACE
@router.post("/login", response_model=Token, summary="Login", description="Authenticate using email/password and receive a JWT and org context.")
async def login(payload: LoginRequest) -> Token:
    """Login with email and password.

    Parameters:
    - payload: LoginRequest with email and password.

    Returns:
    - Token with JWT, token type, expires_in and current org context (first org by default if multiple).
    """
    user = _get_user_by_email(payload.email.lower())
    if not user or not _verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Select a default org context (first membership if any)
    orgs = _list_user_orgs(user["id"])
    current_org = orgs[0] if orgs else None
    expires = timedelta(minutes=JWT_EXPIRES_MINUTES)
    claims = {
        "sub": user["email"],
        "email": user["email"],
        "user_id": user["id"],
        "org_id": current_org["id"] if current_org else None,
        "scope": "user",
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    token = _create_access_token(claims, expires_delta=expires)
    return Token(
        access_token=token,
        token_type="bearer",
        expires_in=int(expires.total_seconds()),
        org=current_org,
    )

# PUBLIC_INTERFACE
@router.get("/me", response_model=UserResponse, summary="Get current user", description="Return the authenticated user and current organization context.")
async def me(ctx: Annotated[dict, Depends(_get_current_user)]) -> UserResponse:
    """Get current user profile information and current org context derived from JWT.

    Parameters:
    - Authorization: Bearer <token> header

    Returns:
    - UserResponse with user info and current org context
    """
    user = ctx["user"]
    org = ctx["org"]
    return UserResponse(
        id=user["id"],
        email=user["email"],
        full_name=user.get("full_name"),
        current_org=org,
    )

# PUBLIC_INTERFACE
@router.post("/orgs/switch", response_model=Token, summary="Switch organization", description="Switch the current organization context and receive a refreshed JWT.")
async def switch_org(payload: SwitchOrgRequest, ctx: Annotated[dict, Depends(_get_current_user)]) -> Token:
    """Switch the authenticated user's current organization and return a refreshed JWT.

    Parameters:
    - Authorization: Bearer <token>
    - payload: SwitchOrgRequest with target org_id

    Returns:
    - Token with updated org_id in claims and current org in response
    """
    user = ctx["user"]
    target_org = _get_org(payload.org_id)
    if not target_org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not _user_has_membership(user["id"], target_org["id"]):
        raise HTTPException(status_code=403, detail="User is not a member of the target organization")

    expires = timedelta(minutes=JWT_EXPIRES_MINUTES)
    claims = {
        "sub": user["email"],
        "email": user["email"],
        "user_id": user["id"],
        "org_id": target_org["id"],
        "scope": "user",
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    token = _create_access_token(claims, expires_delta=expires)
    return Token(
        access_token=token,
        token_type="bearer",
        expires_in=int(expires.total_seconds()),
        org=target_org,
    )
