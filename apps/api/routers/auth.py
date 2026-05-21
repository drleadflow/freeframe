from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import uuid
import secrets
from datetime import datetime, timedelta, timezone
from ..database import get_db
from ..schemas.auth import (
    RegisterRequest, LoginRequest, TokenResponse,
    RefreshRequest, UserResponse, InviteRequest,
    SendMagicCodeRequest, SendMagicCodeResponse,
    VerifyMagicCodeRequest, SetPasswordRequest,
    AcceptInviteRequest, InviteInfoResponse,
)
from ..services.auth_service import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token,
    get_user_by_email, get_user_by_id,
)
from ..services.redis_service import (
    generate_magic_code, store_magic_code, verify_magic_code as redis_verify_magic_code,
    MAGIC_CODE_EXPIRY_SECONDS,
    store_password_setup_token, verify_and_consume_password_setup_token,
)
from ..tasks.email_tasks import send_magic_code_email, send_invite_email
from ..tasks.celery_app import send_task_safe
from ..models.user import User, UserStatus
from ..middleware.auth import get_current_user
from ..middleware.rate_limit import rate_limit

router = APIRouter(prefix="/auth", tags=["auth"])

MAGIC_CODE_EXPIRY_MINUTES = MAGIC_CODE_EXPIRY_SECONDS // 60


def _generate_invite_token() -> str:
    """Generate a secure invite token."""
    return secrets.token_urlsafe(48)


@router.post("/send-magic-code", response_model=SendMagicCodeResponse, dependencies=[Depends(rate_limit("send_magic_code", 5, 600))])
def send_magic_code(body: SendMagicCodeRequest, db: Session = Depends(get_db)):
    """
    Send magic code to email.
    - If user exists: send code for login
    - If user doesn't exist: create pending user and send code
    """
    user = get_user_by_email(db, body.email)
    
    if not user:
        # Check if this is the first user (becomes super admin)
        user_count = db.query(User).filter(User.deleted_at.is_(None)).count()
        is_first_user = user_count == 0
        
        # Create new user in pending_verification status
        user = User(
            email=body.email,
            name=body.email.split("@")[0],  # Temporary name from email
            status=UserStatus.pending_verification,
            email_verified=False,
            is_superadmin=is_first_user,  # First user becomes super admin
        )
        db.add(user)
        db.commit()
    
    # Generate and store magic code in Redis
    code = generate_magic_code()
    store_magic_code(body.email, code)

    # Queue email via Celery (async)
    try:
        send_task_safe(send_magic_code_email, body.email, code, MAGIC_CODE_EXPIRY_MINUTES)
    except Exception:
        pass  # Email delivery is best-effort; code is already in Redis
    
    return SendMagicCodeResponse(
        message="Magic code sent to your email",
        email=body.email,
    )


@router.post("/verify-magic-code", response_model=TokenResponse, dependencies=[Depends(rate_limit("verify_magic_code", 10, 600))])
def verify_magic_code(body: VerifyMagicCodeRequest, db: Session = Depends(get_db)):
    """
    Verify magic code and return tokens.
    Returns needs_password=True if user hasn't set a password yet.
    """
    user = get_user_by_email(db, body.email)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.status == UserStatus.deactivated:
        raise HTTPException(status_code=401, detail="Account deactivated")
    
    # Verify magic code from Redis
    success, error = redis_verify_magic_code(body.email, body.code)
    if not success:
        raise HTTPException(status_code=401, detail=error)
    
    # Mark email as verified
    user.email_verified = True
    
    # If user was pending verification, activate them
    if user.status == UserStatus.pending_verification:
        user.status = UserStatus.active
    
    db.commit()
    
    # Check if user needs to set password
    needs_password = user.password_hash is None
    
    # If password setup is needed, store a one-time setup token so the
    # set-password endpoint can verify the user without relying on
    # localStorage tokens (which can be missing on mobile browsers).
    setup_token: str | None = None
    if needs_password:
        setup_token = secrets.token_urlsafe(32)
        store_password_setup_token(body.email, setup_token)
    
    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
        needs_password=needs_password,
        setup_token=setup_token,
    )


@router.post("/set-password", response_model=TokenResponse)
def set_password(
    body: SetPasswordRequest,
    db: Session = Depends(get_db),
):
    """Set password for a user who just verified via magic code.
    
    Uses a one-time setup token (issued by verify-magic-code) to avoid
    depending on localStorage-stored tokens, which can be unavailable on
    mobile browsers. Returns fresh tokens on success.
    """
    user = get_user_by_email(db, body.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.status == UserStatus.deactivated:
        raise HTTPException(status_code=401, detail="Account deactivated")
    
    # Verify the one-time setup token
    if not body.setup_token or not verify_and_consume_password_setup_token(body.email, body.setup_token):
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")
    
    # Set the password
    user.password_hash = hash_password(body.password)
    user.email_verified = True
    if user.status == UserStatus.pending_verification:
        user.status = UserStatus.active
    db.commit()
    
    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
        needs_password=False,
    )


@router.get("/invite/{token}", response_model=InviteInfoResponse)
def get_invite_info(token: str, db: Session = Depends(get_db)):
    """Get info about an invite token (for the set-password screen)."""
    user = db.query(User).filter(
        User.invite_token == token,
        User.deleted_at.is_(None),
    ).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="Invalid invite link")
    
    if user.invite_token_expires_at and user.invite_token_expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invite link expired")
    
    return InviteInfoResponse(
        email=user.email,
        name=user.name,
    )


@router.post("/accept-invite", response_model=TokenResponse)
def accept_invite(body: AcceptInviteRequest, db: Session = Depends(get_db)):
    """Accept invite and set password. Email is already verified via invite."""
    user = db.query(User).filter(
        User.invite_token == body.token,
        User.deleted_at.is_(None),
    ).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="Invalid invite link")
    
    if user.invite_token_expires_at and user.invite_token_expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invite link expired")
    
    # Set password and activate user
    user.password_hash = hash_password(body.password)
    user.email_verified = True  # Invited users are pre-verified
    user.status = UserStatus.active
    user.invite_token = None
    user.invite_token_expires_at = None
    db.commit()
    
    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
        needs_password=False,
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """Register with email + password (legacy, prefer magic code flow)."""
    if get_user_by_email(db, body.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=body.email,
        name=body.name,
        password_hash=hash_password(body.password),
        status=UserStatus.active,
        email_verified=False,  # Not verified until magic code
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    """Login with email + password."""
    user = get_user_by_email(db, body.email)
    if (
        not user
        or not user.password_hash
        or not verify_password(body.password, user.password_hash)
        or user.status == UserStatus.deactivated
    ):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
        needs_password=False,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(body: RefreshRequest, db: Session = Depends(get_db)):
    payload = decode_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = get_user_by_id(db, uuid.UUID(payload["sub"]))
    if not user or user.status == UserStatus.deactivated:
        raise HTTPException(status_code=401, detail="User not found")
    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
        needs_password=user.password_hash is None,
    )


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.patch("/me/preferences", response_model=UserResponse)
def update_preferences(
    body: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update user preferences (theme, etc). Merges with existing preferences."""
    current_prefs = current_user.preferences or {}
    current_prefs.update(body)
    current_user.preferences = current_prefs
    # Force SQLAlchemy to detect the JSON change
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(current_user, "preferences")
    db.commit()
    db.refresh(current_user)
    return current_user


# ── TEMPORARY: Admin password reset (remove after Emeka is unblocked) ─────────

from pydantic import BaseModel as PydanticBaseModel

class AdminResetPasswordRequest(PydanticBaseModel):
    email: str
    new_password: str
    reset_token: str = ""  # simple gate, remove after use

_ADMIN_RESET_TOKEN = "freeframe-reset-2026"


@router.post("/_reset-password")
def admin_reset_password(body: AdminResetPasswordRequest, db: Session = Depends(get_db)):
    """TEMPORARY: Reset a user's password directly. Remove after founder is unblocked."""
    if body.reset_token != _ADMIN_RESET_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid reset token")

    user = get_user_by_email(db, body.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user.password_hash = hash_password(body.new_password)
    user.email_verified = True
    user.status = UserStatus.active
    db.commit()

    return {
        "message": "Password reset successfully",
        "email": body.email,
        "can_login": True,
    }
