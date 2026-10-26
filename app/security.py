"""Password hashing (stdlib scrypt) and encryption of stored GitLab tokens (Fernet)."""
import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


def _load_or_create_secret() -> bytes:
    """A 32-byte master secret. Taken from VT_SECRET_KEY, else generated once into data_dir."""
    env = os.getenv("VT_SECRET_KEY")
    if env:
        return hashlib.sha256(env.encode()).digest()
    path: Path = settings.data_dir / "secret.key"
    if not path.exists():
        path.write_bytes(secrets.token_bytes(32))
        path.chmod(0o600)
    return path.read_bytes()


_MASTER = _load_or_create_secret()
SESSION_SECRET = hmac.new(_MASTER, b"session", hashlib.sha256).hexdigest()
_fernet = Fernet(base64.urlsafe_b64encode(hmac.new(_MASTER, b"token-encryption", hashlib.sha256).digest()))


def encrypt_token(plain: str) -> str:
    return _fernet.encrypt(plain.encode()).decode()


def decrypt_token(cipher: str) -> str:
    try:
        return _fernet.decrypt(cipher.encode()).decode()
    except InvalidToken as exc:  # secret key changed since the token was saved
        raise ValueError("Stored GitLab token can't be decrypted. Enter it again in Settings.") from exc


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32)
    return hmac.compare_digest(digest.hex(), digest_hex)


def mask_token(token: str) -> str:
    return token[:6] + "…" + token[-4:] if len(token) > 12 else "…"
