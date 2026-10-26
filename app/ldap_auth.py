"""Sign-in with Windows (Active Directory) credentials over LDAP.

Administrators set the directory up on the Admin page; the settings live in the database. A user who signs
in with Windows credentials for the first time gets a profile in the app. The directory checks the password,
so these users can't change or reset it here."""
import logging
import re
import ssl
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from . import app_settings
from .config import settings
from .security import decrypt_token, encrypt_token

log = logging.getLogger(__name__)

DEFAULT_FILTER = "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))"
# AD's "in chain" matching rule: membership through nested groups counts too.
_IN_CHAIN = "1.2.840.113556.1.4.1941"
_CONNECTION_OPTIONS: dict = {}  # tests point this at ldap3's mock directory
_FIELDS = ("enabled", "server_url", "start_tls", "verify_cert", "domain", "base_dn", "bind_dn", "user_filter",
           "required_group", "admin_group")


class LDAPAuthError(Exception):
    """Message is safe to show on the sign-in page."""


class LDAPConfigError(LDAPAuthError):
    """The directory settings are wrong or the server can't be reached; details go to the log."""


@dataclass
class DirectoryUser:
    username: str
    dn: str
    display_name: str | None
    email: str | None
    is_admin: bool | None  # None: no admin group configured, keep the role set in the app


# ---------------------------------------------------------------- settings
def ldap_config(db: Session) -> dict:
    saved = app_settings.load(db, "ldap")
    cfg = {k: saved.get(k, "") for k in _FIELDS}
    cfg["enabled"] = cfg["enabled"] == "true"
    cfg["start_tls"] = cfg["start_tls"] == "true"
    cfg["verify_cert"] = saved.get("verify_cert", "true") != "false"
    cfg["user_filter"] = cfg["user_filter"] or DEFAULT_FILTER
    cfg["bind_password"] = ""
    if saved.get("bind_password"):
        try:
            cfg["bind_password"] = decrypt_token(saved["bind_password"])
        except ValueError:
            log.warning("Saved LDAP service account password can't be decrypted (secret key changed).")
    return cfg


def save_ldap_config(db: Session, values: dict, bind_password: str | None):
    """bind_password None keeps the saved one; "" removes it."""
    out = {k: ("true" if values[k] else "false") if isinstance(values[k], bool) else str(values[k]).strip()
           for k in _FIELDS}
    if bind_password is not None:
        out["bind_password"] = encrypt_token(bind_password) if bind_password else ""
    app_settings.save(db, "ldap", out)


def is_enabled(db: Session) -> bool:
    return app_settings.load(db, "ldap").get("enabled") == "true"


# ---------------------------------------------------------------- directory access
def normalize_username(raw: str) -> str:
    """CORP\\jdoe, jdoe@corp.example.com and jdoe all mean the account jdoe."""
    name = raw.strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.lower()


def _escape(value: str) -> str:
    from ldap3.utils.conv import escape_filter_chars
    return escape_filter_chars(value)


def _server(cfg: dict):
    from ldap3 import Server, Tls
    url = cfg["server_url"]
    if not re.fullmatch(r"ldaps?://[^\s/]+/?", url):
        raise LDAPConfigError("Windows sign-in isn't set up correctly (server URL). Ask an administrator.")
    ca = settings.ca_bundle if settings.ca_bundle and Path(settings.ca_bundle).is_file() else None
    tls = Tls(validate=ssl.CERT_REQUIRED if cfg["verify_cert"] else ssl.CERT_NONE,
              ca_certs_file=ca if cfg["verify_cert"] else None)
    return Server(url.rstrip("/"), use_ssl=url.startswith("ldaps://"), tls=tls, connect_timeout=5)


def _bind(server, cfg: dict, who: str, password: str):
    """A bound connection, or None when the directory rejects the credentials."""
    from ldap3 import Connection
    from ldap3.core.exceptions import LDAPException
    try:
        conn = Connection(server, user=who, password=password, receive_timeout=10, raise_exceptions=False,
                          read_only=True, **_CONNECTION_OPTIONS)
        conn.open()
        if cfg["start_tls"] and not cfg["server_url"].startswith("ldaps://"):
            conn.start_tls()
        if conn.bind():
            return conn
        conn.unbind()
        return None
    except LDAPException as exc:
        log.warning("LDAP server %s: %s", cfg["server_url"], exc)
        raise LDAPConfigError("The Windows sign-in server can't be reached. Try again later or ask an administrator.") from exc


def _find_user(conn, cfg: dict, username: str):
    from ldap3 import SUBTREE
    flt = cfg["user_filter"].replace("{username}", _escape(username))
    conn.search(cfg["base_dn"], flt, search_scope=SUBTREE, size_limit=2,
                attributes=["sAMAccountName", "displayName", "mail", "userPrincipalName"])
    return conn.entries[0] if len(conn.entries) == 1 else None


def _member_of(conn, user_dn: str, group_dn: str) -> bool:
    from ldap3 import BASE
    conn.search(user_dn, f"(memberOf:{_IN_CHAIN}:={_escape(group_dn)})", search_scope=BASE, attributes=[])
    return bool(conn.entries)


def _attr(entry, name: str) -> str | None:
    try:
        value = entry[name].value
    except Exception:  # noqa: BLE001 - attribute missing on this entry
        return None
    return str(value) if value else None


def authenticate(cfg: dict, raw_username: str, password: str) -> DirectoryUser:
    wrong = LDAPAuthError("Username or password is wrong.")
    username = normalize_username(raw_username)
    # An empty password would be an anonymous bind, which many directories accept.
    if not password or not re.fullmatch(r"[\w.$'-][\w .$'-]{0,63}", username):
        raise wrong
    if not cfg["base_dn"]:
        raise LDAPConfigError("Windows sign-in isn't set up correctly (base DN). Ask an administrator.")
    server = _server(cfg)

    if cfg["bind_dn"]:
        # Look the account up with the service account, then check the password by binding as the user.
        search = _bind(server, cfg, cfg["bind_dn"], cfg["bind_password"])
        if search is None:
            log.warning("LDAP service account %s was rejected by %s", cfg["bind_dn"], cfg["server_url"])
            raise LDAPConfigError("Windows sign-in isn't set up correctly (service account). Ask an administrator.")
        try:
            entry = _find_user(search, cfg, username)
            if entry is None:
                raise wrong
            user_conn = _bind(server, cfg, entry.entry_dn, password)
            if user_conn is None:
                raise wrong
            user_conn.unbind()
            return _directory_user(search, cfg, entry, username)
        finally:
            search.unbind()

    # No service account: bind as the user with user@domain, then read the account with that connection.
    if not cfg["domain"]:
        raise LDAPConfigError("Windows sign-in isn't set up correctly (domain). Ask an administrator.")
    conn = _bind(server, cfg, f"{username}@{cfg['domain']}", password)
    if conn is None:
        raise wrong
    try:
        entry = _find_user(conn, cfg, username)
        if entry is None:
            raise LDAPConfigError("Your Windows account was accepted but couldn't be found under the base DN. "
                                  "Ask an administrator.")
        return _directory_user(conn, cfg, entry, username)
    finally:
        conn.unbind()


def _directory_user(conn, cfg: dict, entry, username: str) -> DirectoryUser:
    if cfg["required_group"] and not _member_of(conn, entry.entry_dn, cfg["required_group"]):
        raise LDAPAuthError("Your Windows account isn't allowed to use this app. Ask an administrator for access.")
    is_admin = _member_of(conn, entry.entry_dn, cfg["admin_group"]) if cfg["admin_group"] else None
    return DirectoryUser(username=(_attr(entry, "sAMAccountName") or username).lower(), dn=entry.entry_dn,
                         display_name=_attr(entry, "displayName"), email=_attr(entry, "mail"), is_admin=is_admin)


def test_connection(cfg: dict, lookup: str = "") -> str:
    """For the Admin page: reach the server, bind the service account, optionally find one account."""
    server = _server(cfg)
    if not cfg["bind_dn"]:
        conn = _bind(server, cfg, "", "")  # anonymous: only proves the server answers
        if conn:
            conn.unbind()
        return (f"Reached {cfg['server_url']}. Without a service account, accounts can only be looked up while a "
                "user signs in, so try signing in with a Windows account to finish the check.")
    conn = _bind(server, cfg, cfg["bind_dn"], cfg["bind_password"])
    if conn is None:
        raise LDAPAuthError(f"Reached {cfg['server_url']}, but the service account was rejected. Check its DN and password.")
    try:
        if not lookup:
            return f"Reached {cfg['server_url']} and signed in with the service account."
        entry = _find_user(conn, cfg, normalize_username(lookup))
        if entry is None:
            raise LDAPAuthError(f"Signed in with the service account, but no account matches {lookup!r} "
                                "under the base DN with the user filter.")
        notes = [f"Found {entry.entry_dn}."]
        if cfg["required_group"]:
            notes.append("It is in the allowed group." if _member_of(conn, entry.entry_dn, cfg["required_group"])
                         else "It is NOT in the allowed group, so it can't sign in.")
        if cfg["admin_group"]:
            notes.append("It is in the admin group." if _member_of(conn, entry.entry_dn, cfg["admin_group"])
                         else "It isn't in the admin group.")
        return " ".join(notes)
    finally:
        conn.unbind()
