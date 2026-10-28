"""Sign-in with GitLab (OAuth 2 authorization code flow with PKCE).

Administrators register this app as an application in GitLab and enter its ID and secret on the Admin page.
Signing in gives the app the user's GitLab token, so they don't paste one in Settings. GitLab OAuth access
tokens expire after two hours; token_for() renews them with the refresh token, which GitLab rotates on use."""
import base64
import hashlib
import json
import logging
import secrets
import threading
import time
from datetime import timedelta
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import app_settings
from .config import settings
from .db import SessionLocal, User, utcnow
from .security import decrypt_token, encrypt_token

log = logging.getLogger(__name__)

SCOPES = "api read_repository"
CALLBACK_PATH = "/login/gitlab/callback"
FLOW_TTL_S = 600  # the sign-in has to finish within this time
RENEW_BEFORE = timedelta(minutes=5)
EXPIRED = "Your GitLab sign-in has expired. Sign out and sign in with GitLab again."
_lock = threading.Lock()  # one renewal at a time in this process; the row lock covers other processes


class OAuthError(Exception):
    """Message is safe to show to the user."""


# ---------------------------------------------------------------- settings
def oauth_config(db: Session) -> dict:
    """What an administrator saved on the Admin page, else the .env values."""
    saved = app_settings.load(db, "gitlab_oauth")
    cfg = {"enabled": saved.get("enabled", "true" if settings.gitlab_oauth_id else "false") == "true",
           "app_id": saved.get("app_id") or settings.gitlab_oauth_id,
           "app_url": (saved.get("app_url") or settings.public_url).rstrip("/"),
           "secret": settings.gitlab_oauth_secret}
    if saved.get("secret"):
        try:
            cfg["secret"] = decrypt_token(saved["secret"])
        except ValueError:
            log.warning("Saved GitLab application secret can't be decrypted (secret key changed).")
    return cfg


def save_oauth_config(db: Session, enabled: bool, app_id: str, app_url: str, secret: str | None):
    """secret None keeps the saved one."""
    values = {"enabled": "true" if enabled else "false", "app_id": app_id.strip(), "app_url": app_url.strip().rstrip("/")}
    if secret is not None:
        values["secret"] = encrypt_token(secret) if secret else ""
    app_settings.save(db, "gitlab_oauth", values)


def is_enabled(db: Session) -> bool:
    cfg = oauth_config(db)
    return cfg["enabled"] and bool(cfg["app_id"] and cfg["secret"])


def redirect_uri(cfg: dict, base_url: str) -> str:
    """The callback URL GitLab sends users back to; it must match the one registered in GitLab exactly."""
    return (cfg["app_url"] or base_url.rstrip("/")) + CALLBACK_PATH


# ---------------------------------------------------------------- the sign-in flow
def start(cfg: dict, callback: str) -> tuple[str, str]:
    """Returns (GitLab authorize URL, sealed flow state for a short-lived cookie)."""
    state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urlencode({"client_id": cfg["app_id"], "redirect_uri": callback, "response_type": "code",
                       "scope": SCOPES, "state": state, "code_challenge": challenge,
                       "code_challenge_method": "S256"})
    sealed = encrypt_token(json.dumps({"state": state, "verifier": verifier, "at": time.time()}))
    return f"{settings.gitlab_url}/oauth/authorize?{query}", sealed


def verifier_for(sealed: str | None, state: str) -> str:
    """The PKCE verifier of this browser's sign-in, if `state` is the one it started with."""
    try:
        flow = json.loads(decrypt_token(sealed or ""))
    except (ValueError, TypeError):
        raise OAuthError("The sign-in didn't start here or took too long. Try again.") from None
    if not secrets.compare_digest(flow.get("state", ""), state or "") or time.time() - flow["at"] > FLOW_TTL_S:
        raise OAuthError("The sign-in didn't start here or took too long. Try again.")
    return flow["verifier"]


def _token_request(cfg: dict, data: dict) -> dict:
    try:
        r = httpx.post(f"{settings.gitlab_url}/oauth/token", verify=settings.tls_verify, timeout=30,
                       data={"client_id": cfg["app_id"], "client_secret": cfg["secret"], **data})
    except httpx.HTTPError as exc:
        raise OAuthError(f"Can't reach GitLab at {settings.gitlab_url}: {exc}") from exc
    if r.status_code != 200:
        log.warning("GitLab token request (%s) failed: %s %s", data.get("grant_type"), r.status_code, r.text[:300])
        raise OAuthError(EXPIRED if data.get("grant_type") == "refresh_token"
                         else "GitLab didn't accept the sign-in. Check the application settings on the Admin page.")
    return r.json()


def exchange_code(cfg: dict, code: str, verifier: str, callback: str) -> dict:
    return _token_request(cfg, {"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                                "redirect_uri": callback})


def store_tokens(user: User, tokens: dict):
    user.gitlab_token_enc = encrypt_token(tokens["access_token"])
    user.gitlab_token_type = "oauth"
    user.gitlab_refresh_enc = encrypt_token(tokens["refresh_token"]) if tokens.get("refresh_token") else None
    expires = tokens.get("expires_in")
    user.gitlab_token_expires_at = utcnow() + timedelta(seconds=int(expires)) if expires else None


# ---------------------------------------------------------------- keeping the token valid
def _expired(user: User) -> bool:
    at = user.gitlab_token_expires_at
    if at is None:
        return False
    if at.tzinfo is None:  # SQLite drops the time zone
        at = at.replace(tzinfo=utcnow().tzinfo)
    return at - RENEW_BEFORE <= utcnow()


def token_for(user_id: int, force: bool = False) -> str:
    """The user's GitLab token, renewed first if it is a GitLab sign-in token about to expire (or `force`).

    Raises OAuthError when it can't be renewed; the token is then cleared, so the user signs in again."""
    with _lock, SessionLocal() as db:
        user = db.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None or not user.gitlab_token_enc:
            raise OAuthError("Add your GitLab token in Settings first.")
        if not user.gitlab_refresh_enc or not (force or _expired(user)):
            db.rollback()
            return decrypt_token(user.gitlab_token_enc)
        cfg = oauth_config(db)
        try:
            tokens = _token_request(cfg, {"grant_type": "refresh_token",
                                          "refresh_token": decrypt_token(user.gitlab_refresh_enc)})
        except OAuthError:
            if cfg["app_id"] and cfg["secret"]:  # GitLab refused the refresh token: it was revoked or used up
                user.gitlab_token_enc = user.gitlab_refresh_enc = user.gitlab_token_expires_at = None
                db.commit()
            raise
        store_tokens(user, tokens)
        db.commit()
        log.info("Renewed the GitLab sign-in token of %s", user.username)
        return tokens["access_token"]


def refresher(user_id: int):
    """For GitLabClient: renews the token when GitLab rejects it mid-way (e.g. an analysis running for hours)."""
    return lambda: token_for(user_id, force=True)
