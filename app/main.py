"""Web app: sign-in, per-user GitLab token settings, commit picker, job results and write-back actions."""
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import ldap_auth, prompts, report, worker
from .analyzer import DEFAULT_SEVERITIES, SEVERITIES
from .config import settings
from .db import AnalysisJob, Finding, ProjectConfig, User, get_db, init_db, utcnow
from .gitlab_client import GitLabClient, GitLabError
from .llm_client import (MAX_TOKENS_RANGE, LLMClient, llm_config, llm_overrides, reset_llm_config,
                         save_llm_config)
from .patcher import EditError, apply_edits
from .security import SESSION_SECRET, decrypt_token, encrypt_token, hash_password, mask_token, verify_password

logging.basicConfig(level=os.getenv("VT_LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # request URLs at INFO are noise
log = logging.getLogger(__name__)
BASE = Path(__file__).parent
USERNAME_RE = r"[a-z0-9._-]{3,80}"


@asynccontextmanager
async def lifespan(_app):
    init_db()
    if os.getenv("VT_EMBEDDED_WORKER", "true").lower() != "false":
        worker.start()
    yield
    worker.stop()


app = FastAPI(title="Vulnerability triage", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, session_cookie="vt_session",
                   same_site="strict", https_only=settings.session_cookie_secure, max_age=12 * 3600)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.filters["ago"] = lambda d: d.strftime("%Y-%m-%d %H:%M UTC") if d else ""
templates.env.globals["icon"] = lambda name, cls="i": Markup(
    f'<svg class="{escape(cls)}" aria-hidden="true" focusable="false"><use href="/static/icons.svg#{escape(name)}"/></svg>')


# ------------------------------------------------------------------ auth helpers
class NeedsLogin(Exception):
    pass


@app.exception_handler(NeedsLogin)
async def _needs_login(request: Request, _exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Sign in again; your session has ended."}, status_code=401)
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(GitLabError)
async def _gitlab_error(_request: Request, exc: GitLabError):
    return JSONResponse({"detail": str(exc)}, status_code=502 if exc.status in (None, 500) else exc.status)


def csrf_token(request: Request) -> str:
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(32)
    return request.session["csrf"]


def check_csrf(request: Request, form_value: str | None = None):
    expected = request.session.get("csrf")
    sent = form_value or request.headers.get("x-csrf-token")
    if not expected or not sent or not secrets.compare_digest(expected, sent):
        raise HTTPException(403, "The form expired. Reload the page and try again.")


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get("uid")
    user = db.get(User, uid) if uid else None
    if not user:
        raise NeedsLogin()
    return user


def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(403, "Only administrators can do this.")
    return user


def gitlab_for(user: User) -> GitLabClient:
    if not user.gitlab_token_enc:
        raise HTTPException(400, "Add your GitLab token in Settings first.")
    try:
        return GitLabClient(decrypt_token(user.gitlab_token_enc), user.gitlab_token_type)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def back_to_settings(saved: str = "", error: str = "") -> RedirectResponse:
    q = urlencode({k: v for k, v in (("saved", saved), ("error", error)) if v})
    return RedirectResponse(f"/settings?{q}", status_code=303)


def back_to_admin(section: str, saved: str = "", error: str = "") -> RedirectResponse:
    q = urlencode({k: v for k, v in (("saved", saved), ("error", error), ("section", section)) if v})
    return RedirectResponse(f"/admin?{q}#{section}", status_code=303)


def render(request: Request, name: str, user: User | None, **ctx):
    return templates.TemplateResponse(request, name, {"user": user, "csrf": csrf_token(request),
                                                      "gitlab_url": settings.gitlab_url, **ctx})


# ------------------------------------------------------------------ sign in / register
def _first_run(db: Session) -> bool:
    return db.scalar(select(func.count(User.id))) == 0


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if _first_run(db):  # the only self-service account: the first administrator
        return RedirectResponse("/register", status_code=303)
    return render(request, "auth.html", None, mode="login", windows=ldap_auth.is_enabled(db))


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), csrf: str = Form(""),
          db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    raw = username.strip()
    windows = ldap_auth.is_enabled(db)

    def fail(message: str = "Username or password is wrong."):
        return render(request, "auth.html", None, mode="login", error=message, windows=windows, username=raw)

    user = db.scalar(select(User).where(User.username == raw.lower()))
    if user and not user.is_windows:
        if not verify_password(password, user.password_hash):
            return fail()
    elif windows:
        try:
            found = ldap_auth.authenticate(ldap_auth.ldap_config(db), raw, password)
        except ldap_auth.LDAPAuthError as exc:
            return fail(str(exc))
        user = db.scalar(select(User).where(User.username == found.username))
        if user and not user.is_windows:
            return fail("A local account with this username already exists, so Windows sign-in can't use it. "
                        "Ask an administrator.")
        if not user:  # first Windows sign-in: create the profile
            user = User(username=found.username, password_hash="windows", auth_source="ldap", is_admin=False)
            db.add(user)
            log.info("Created a profile for Windows user %s (%s)", found.username, found.dn)
        user.display_name, user.email = found.display_name, found.email
        if found.is_admin is not None:  # an admin group is configured: it decides the role
            user.is_admin = found.is_admin
    else:
        return fail()
    user.last_login_at = utcnow()
    db.commit()
    request.session.clear()
    request.session["uid"] = user.id
    return RedirectResponse("/" if user.gitlab_token_enc else "/settings", status_code=303)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, db: Session = Depends(get_db)):
    if not _first_run(db):
        return RedirectResponse("/login", status_code=303)
    return render(request, "auth.html", None, mode="register")


@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...), csrf: str = Form(""),
             db: Session = Depends(get_db)):
    """Only creates the first administrator. Later accounts come from the Admin page or Windows sign-in."""
    check_csrf(request, csrf)
    if not _first_run(db):
        raise HTTPException(403, "Accounts are created by an administrator, or on first Windows sign-in.")
    username = username.strip().lower()
    error = None
    if not re.fullmatch(USERNAME_RE, username):
        error = "Use 3–80 letters, digits, dots, dashes or underscores for the username."
    elif len(password) < 12:
        error = "Use a password of at least 12 characters."
    if error:
        return render(request, "auth.html", None, mode="register", error=error, username=username)
    user = User(username=username, password_hash=hash_password(password), is_admin=True, last_login_at=utcnow())
    db.add(user)
    db.commit()
    request.session.clear()
    request.session["uid"] = user.id
    return RedirectResponse("/settings", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ------------------------------------------------------------------ settings
@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user: User = Depends(current_user), saved: str = "", error: str = ""):
    masked = None
    if user.gitlab_token_enc:
        try:
            masked = mask_token(decrypt_token(user.gitlab_token_enc))
        except ValueError:
            masked = "unreadable — enter it again"
    return render(request, "settings.html", user, masked=masked, saved=saved, error=error)


@app.post("/settings/token")
def save_token(request: Request, token: str = Form(...), token_type: str = Form("access_token"),
               csrf: str = Form(""), user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    token = token.strip()
    token_type = "oauth" if token_type == "oauth" else "access_token"
    try:
        with GitLabClient(token, token_type) as gl:
            me = gl.current_user()
            scopes = gl.token_scopes()
    except GitLabError as exc:
        return back_to_settings(error=str(exc))
    if scopes and not ({"api"} & set(scopes) or {"read_api"} & set(scopes)):
        return back_to_settings(error="The token needs the read_api scope (api to write back to GitLab).")
    user.gitlab_token_enc = encrypt_token(token)
    user.gitlab_token_type = token_type
    user.gitlab_username = me.get("username")
    db.commit()
    _forget_access(user.id)  # project roles are checked again with the new token
    note = "" if not scopes or "api" in scopes else " It can read but not write back; add the api scope for issues and merge requests."
    return back_to_settings(saved=f"Connected to GitLab as {me.get('username')}.{note}")


@app.post("/settings/token/delete")
def delete_token(request: Request, csrf: str = Form(""), user: User = Depends(current_user),
                 db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    user.gitlab_token_enc, user.gitlab_username = None, None
    db.commit()
    _forget_access(user.id)
    return back_to_settings(saved="Token removed.")


@app.post("/settings/password")
def change_password(request: Request, current: str = Form(...), new: str = Form(...), csrf: str = Form(""),
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    if user.is_windows:
        return back_to_settings(error="You sign in with your Windows account; change its password in Windows.")
    if not verify_password(current, user.password_hash):
        return back_to_settings(error="Your current password is wrong.")
    if len(new) < 12:
        return back_to_settings(error="Use a password of at least 12 characters.")
    user.password_hash = hash_password(new)
    db.commit()
    return back_to_settings(saved="Password changed.")


# ------------------------------------------------------------------ admin
@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, user: User = Depends(admin_user), db: Session = Depends(get_db),
               saved: str = "", error: str = "", section: str = ""):
    users = db.scalars(select(User).where(User.password_hash != "disabled").order_by(User.username)).all()
    configs = db.scalars(select(ProjectConfig).order_by(ProjectConfig.gitlab_project_id)).all()
    cfg = llm_config(db)  # secrets never go to the page, only whether one is saved
    llm = {**cfg, "api_key": None, "has_key": bool(cfg["api_key"]) and cfg["api_key"] != "EMPTY",
           "overridden": bool(llm_overrides(db))}
    ldap = ldap_auth.ldap_config(db)
    ldap = {**ldap, "has_bind_password": bool(ldap["bind_password"]), "bind_password": None}
    return render(request, "admin.html", user, users=users, configs=configs, llm=llm, ldap=ldap,
                  saved=saved, error=error, section=section)


@app.post("/admin/llm")
def save_llm(request: Request, base_url: str = Form(...), model: str = Form(...), api_key: str = Form(""),
             clear_key: str = Form(""), structured_output: str = Form(""), timeout_s: str = Form("900"),
             parallel: str = Form(""), max_tokens: str = Form(""), thinking: str = Form(""), csrf: str = Form(""),
             user: User = Depends(admin_user),
             db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    base_url, model = base_url.strip().rstrip("/"), model.strip()
    if not re.fullmatch(r"https?://\S+", base_url):
        return back_to_admin("model", error="The vLLM URL must start with http:// or https://, e.g. http://vllm.internal:8000/v1.")
    if not model:
        return back_to_admin("model", error="Enter the served model name.")
    if not timeout_s.strip().isdigit() or not 10 <= int(timeout_s) <= 3600:
        return back_to_admin("model", error="Use a timeout between 10 and 3600 seconds.")
    parallel = parallel.strip()
    if parallel and (not parallel.isdigit() or not 1 <= int(parallel) <= 32):
        return back_to_admin("model", error="Use between 1 and 32 parallel requests.")
    max_tokens = max_tokens.strip()
    low, high = MAX_TOKENS_RANGE
    if max_tokens and (not max_tokens.isdigit() or not low <= int(max_tokens) <= high):
        return back_to_admin("model", error=f"Use a reply limit between {low} and {high} tokens.")
    key = "EMPTY" if clear_key else (api_key.strip() or None)
    save_llm_config(db, base_url, model, bool(structured_output), int(timeout_s), key,
                    int(parallel) if parallel else None, int(max_tokens) if max_tokens else None,
                    thinking == "on" if thinking in ("on", "off") else None)
    log.info("%s changed the vLLM settings (%s, %s, %s parallel)", user.username, base_url, model, parallel or "default")
    return back_to_admin("model", saved="Model settings saved. New analyses use them; running ones keep the old settings.")


@app.post("/admin/llm/reset")
def reset_llm(request: Request, csrf: str = Form(""), user: User = Depends(admin_user),
              db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    reset_llm_config(db)
    return back_to_admin("model", saved="Model settings reset to the values in .env.")


def _ldap_form(enabled: str, server_url: str, start_tls: str, verify_cert: str, domain: str, base_dn: str,
               bind_dn: str, user_filter: str, required_group: str, admin_group: str) -> tuple[dict, str]:
    values = {"enabled": bool(enabled), "server_url": server_url.strip().rstrip("/"), "start_tls": bool(start_tls),
              "verify_cert": bool(verify_cert), "domain": domain.strip().lstrip("@"), "base_dn": base_dn.strip(),
              "bind_dn": bind_dn.strip(), "user_filter": user_filter.strip() or ldap_auth.DEFAULT_FILTER,
              "required_group": required_group.strip(), "admin_group": admin_group.strip()}
    error = ""
    if values["server_url"] and not re.fullmatch(r"ldaps?://[^\s/]+", values["server_url"]):
        error = "The server URL must look like ldaps://dc01.corp.example.com:636 or ldap://dc01.corp.example.com:389."
    elif "{username}" not in values["user_filter"]:
        error = "The user filter must contain {username}."
    elif values["enabled"] and not (values["server_url"] and values["base_dn"]):
        error = "To turn Windows sign-in on, enter at least the server URL and the base DN."
    elif values["enabled"] and not (values["bind_dn"] or values["domain"]):
        error = "Enter a service account, or the domain users sign in with (e.g. corp.example.com)."
    return values, error


@app.post("/admin/ldap")
def save_ldap(request: Request, enabled: str = Form(""), server_url: str = Form(""), start_tls: str = Form(""),
              verify_cert: str = Form(""), domain: str = Form(""), base_dn: str = Form(""), bind_dn: str = Form(""),
              bind_password: str = Form(""), clear_bind_password: str = Form(""), user_filter: str = Form(""),
              required_group: str = Form(""), admin_group: str = Form(""), csrf: str = Form(""),
              user: User = Depends(admin_user), db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    values, error = _ldap_form(enabled, server_url, start_tls, verify_cert, domain, base_dn, bind_dn, user_filter,
                               required_group, admin_group)
    if error:
        return back_to_admin("windows", error=error)
    password = "" if clear_bind_password else (bind_password or None)
    ldap_auth.save_ldap_config(db, values, password)
    log.info("%s changed the Windows sign-in settings (enabled=%s, %s)", user.username, values["enabled"],
             values["server_url"])
    state = "on" if values["enabled"] else "off"
    return back_to_admin("windows", saved=f"Windows sign-in settings saved. Windows sign-in is {state}.")


@app.post("/admin/ldap/test")
def test_ldap(request: Request, lookup: str = Form(""), csrf: str = Form(""), user: User = Depends(admin_user),
              db: Session = Depends(get_db)):
    """Tests the saved settings, so save first."""
    check_csrf(request, csrf)
    cfg = ldap_auth.ldap_config(db)
    if not cfg["server_url"]:
        return back_to_admin("windows", error="Save a server URL first.")
    try:
        return back_to_admin("windows", saved="Test passed. " + ldap_auth.test_connection(cfg, lookup.strip()))
    except ldap_auth.LDAPAuthError as exc:
        return back_to_admin("windows", error=f"Test failed. {exc} Details are in the web container's log.")


@app.post("/admin/users")
def create_user(request: Request, username: str = Form(...), password: str = Form(...), csrf: str = Form(""),
                user: User = Depends(admin_user), db: Session = Depends(get_db)):
    """Local accounts. Windows users don't need one: their profile is created when they first sign in."""
    check_csrf(request, csrf)
    username = username.strip().lower()
    if not re.fullmatch(USERNAME_RE, username):
        return back_to_admin("users", error="Use 3–80 letters, digits, dots, dashes or underscores for the username.")
    if len(password) < 12:
        return back_to_admin("users", error="Use a temporary password of at least 12 characters.")
    if db.scalar(select(User).where(User.username == username)):
        return back_to_admin("users", error=f"The username {username} is taken.")
    db.add(User(username=username, password_hash=hash_password(password)))
    db.commit()
    return back_to_admin("users", saved=f"Added {username}. Give them the temporary password; they can change it in Settings.")


@app.post("/admin/users/{uid}/toggle-admin")
def toggle_admin(uid: int, request: Request, csrf: str = Form(""), user: User = Depends(admin_user),
                 db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    target = db.get(User, uid)
    if target and target.id != user.id:
        target.is_admin = not target.is_admin
        db.commit()
        return back_to_admin("users", saved=f"{target.username} is now {'an administrator' if target.is_admin else 'a user'}.")
    return back_to_admin("users")


@app.post("/admin/users/{uid}/delete")
def delete_user(uid: int, request: Request, csrf: str = Form(""), user: User = Depends(admin_user),
                db: Session = Depends(get_db)):
    check_csrf(request, csrf)
    target = db.get(User, uid)
    if target and target.id != user.id:
        name = target.username
        target.gitlab_token_enc = None
        target.password_hash = "disabled"
        target.username = f"deleted-{target.id}-{target.username}"[:80]
        db.commit()
        return back_to_admin("users", saved=f"Deleted {name}. Their analyses stay in the history.")
    return back_to_admin("users")


@app.post("/admin/projects")
def save_project_config(request: Request, project_id: int = Form(...), build_cmd: str = Form(""),
                        test_cmd: str = Form(""), rescan_cmd: str = Form(""), csrf: str = Form(""),
                        user: User = Depends(admin_user), db: Session = Depends(get_db)):
    """Validation commands run on the server, so only administrators can set them."""
    check_csrf(request, csrf)
    cfg = db.scalar(select(ProjectConfig).where(ProjectConfig.gitlab_project_id == project_id))
    if not cfg:
        cfg = ProjectConfig(gitlab_project_id=project_id)
        db.add(cfg)
    cfg.build_cmd, cfg.test_cmd, cfg.rescan_cmd, cfg.updated_by = build_cmd, test_cmd, rescan_cmd, user.id
    db.commit()
    return back_to_admin("validation", saved=f"Saved the validation commands for project {project_id}.")


# ------------------------------------------------------------------ pages
@app.get("/", response_class=HTMLResponse)
def home_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    mine = AnalysisJob.user_id == user.id
    verdicts = dict(db.execute(select(Finding.verdict, func.count()).join(AnalysisJob).where(mine)
                               .group_by(Finding.verdict)).all())
    stats = {"jobs": db.scalar(select(func.count(AnalysisJob.id)).where(mine)) or 0,
             "real": verdicts.get("true_positive", 0), "review": verdicts.get("needs_review", 0),
             "fp": verdicts.get("false_positive", 0)}
    recent = db.scalars(select(AnalysisJob).where(mine).order_by(AnalysisJob.id.desc()).limit(8)).all()
    active = db.scalar(select(func.count(AnalysisJob.id)).where(AnalysisJob.status.in_(["queued", "running"]))) or 0
    return render(request, "home.html", user, stats=stats, recent=recent, active=active)


@app.get("/analyze", response_class=HTMLResponse)
def analyze_page(request: Request, user: User = Depends(current_user)):
    if not user.gitlab_token_enc:
        return back_to_settings(error="Add your GitLab token to start.")
    return render(request, "analyze.html", user, severities=SEVERITIES, default_severities=DEFAULT_SEVERITIES,
                  default_thinking="on" if llm_config()["thinking"] else "off")


@app.get("/history", response_class=HTMLResponse)
def history_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db),
                 scope: str = "mine", all: int = 0):
    """mine: analyses the user started. shared: other users' analyses of projects where the user is at least
    Developer in GitLab (read-only). all: every analysis (administrators)."""
    if all:
        scope = "all"
    if scope not in ("mine", "shared", "all") or (scope == "all" and not user.is_admin):
        scope = "mine"
    q = select(AnalysisJob).order_by(AnalysisJob.id.desc()).limit(200)
    shared_error = ""
    if scope == "mine":
        jobs = db.scalars(q.where(AnalysisJob.user_id == user.id)).all()
    elif scope == "all":
        jobs = db.scalars(q).all()
    elif not user.gitlab_token_enc:
        jobs, shared_error = [], "token"
    else:
        others = db.scalars(q.where(AnalysisJob.user_id != user.id)).all()
        with gitlab_for(user) as gl:  # one GitLab check per project, cached
            allowed = {pid for pid in {j.project_id for j in others} if _can_view_project(user, pid, gl)}
        jobs = [j for j in others if j.project_id in allowed]
    counts = {}
    for job_id, verdict, n in db.execute(select(Finding.job_id, Finding.verdict, func.count())
                                         .where(Finding.job_id.in_([j.id for j in jobs]))
                                         .group_by(Finding.job_id, Finding.verdict)):
        counts.setdefault(job_id, {})[verdict or "other"] = n
    return render(request, "history.html", user, jobs=jobs, counts=counts, scope=scope, shared_error=shared_error)


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_page(job_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    job = _job_for(job_id, user, db)
    return render(request, "job.html", user, job=job, can_act=job.user_id == user.id)


@app.get("/jobs/{job_id}/report.xlsx")
def job_report(job_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """The analysis as an Excel workbook: a summary and one row per finding with its GitLab links."""
    job = _job_for(job_id, user, db)
    return Response(report.build_report(job, settings.gitlab_url, user.username), media_type=report.MIME,
                    headers={"Content-Disposition": f'attachment; filename="{report.filename(job)}"',
                             "Cache-Control": "no-store"})


@app.get("/healthz", include_in_schema=False)
def healthz(db: Session = Depends(get_db)):
    """Liveness for Docker: the app is up and its database answers."""
    db.execute(select(1))
    return {"ok": True}


# ------------------------------------------------------------------ API: picker
@app.get("/api/health")
def health(user: User = Depends(current_user)):
    llm = LLMClient()
    try:
        llm_state = llm.health()
    finally:
        llm.close()
    if not user.is_admin:  # model names and server details are for the Admin page
        llm_state = {"ok": llm_state["ok"], "detail": "" if llm_state["ok"] else "The local model isn't available. Tell an administrator."}
    gl_state = {"ok": False, "detail": "No token in Settings."}
    if user.gitlab_token_enc:
        try:
            with gitlab_for(user) as gl:
                gl_state = {"ok": True, "detail": f"Signed in as {gl.current_user()['username']}"}
        except (GitLabError, HTTPException) as exc:
            gl_state = {"ok": False, "detail": getattr(exc, "detail", str(exc))}
    return {"llm": llm_state, "gitlab": gl_state}


@app.get("/api/projects")
def api_projects(search: str = "", user: User = Depends(current_user)):
    with gitlab_for(user) as gl:
        return [{"id": p["id"], "path": p["path_with_namespace"], "name": p["name_with_namespace"],
                 "group": (p.get("namespace") or {}).get("full_path") or p["path_with_namespace"].rsplit("/", 1)[0],
                 "default_branch": p.get("default_branch"), "web_url": p.get("web_url")}
                for p in gl.projects(search)]


@app.get("/api/projects/{pid}/branches")
def api_branches(pid: int, search: str = "", user: User = Depends(current_user)):
    with gitlab_for(user) as gl:
        return [{"name": b["name"], "default": b.get("default"), "sha": b["commit"]["id"],
                 "committed_date": b["commit"].get("committed_date")} for b in gl.branches(pid, search)]


@app.get("/api/projects/{pid}/commits")
def api_commits(pid: int, ref: str, page: int = 1, user: User = Depends(current_user),
                db: Session = Depends(get_db)):
    with gitlab_for(user) as gl:
        commits = gl.commits(pid, ref, page)
    shas = [c["id"] for c in commits]
    latest, others_visible = {}, None
    for job in db.scalars(select(AnalysisJob).where(AnalysisJob.project_id == pid, AnalysisJob.sha.in_(shas))
                          .order_by(AnalysisJob.id)):
        if job.user_id != user.id and not user.is_admin:  # other users' analyses: only for Developer or higher
            if others_visible is None:
                others_visible = _can_view_project(user, pid)
            if not others_visible:
                continue
        latest[job.sha] = {"id": job.id, "status": job.status, "by": job.user.username}
    return [{"sha": c["id"], "short": c["short_id"], "title": c["title"], "author": c["author_name"],
             "date": c["committed_date"], "web_url": c.get("web_url"), "job": latest.get(c["id"])} for c in commits]


@app.get("/api/projects/{pid}/commits/{sha}/scan")
def api_scan(pid: int, sha: str, path: str, detail: int = 0, user: User = Depends(current_user)):
    """SAST scan state of a commit; detail=1 adds the findings per severity (the selected commit only)."""
    with gitlab_for(user) as gl:
        scan = gl.scan_status(pid, sha)
        if scan["state"] == "finished" and scan.get("pipeline_iid"):
            scan["finding_count"] = gl.sast_finding_count(path, scan["pipeline_iid"])
            if detail:
                scan["severity_counts"] = gl.sast_severity_counts(path, scan["pipeline_iid"])
        return scan


# ------------------------------------------------------------------ API: jobs
class JobIn(BaseModel):
    project_id: int
    project_path: str
    branch: str
    sha: str
    severities: list[str] = DEFAULT_SEVERITIES
    thinking: str | None = None  # on|off; None: the default on the Admin page


class RerunIn(BaseModel):
    thinking: str | None = None


DEVELOPER = 30  # GitLab shows a project's vulnerabilities from this role up, so other users' analyses do too
ACCESS_TTL = 300
_access: dict[tuple[int, int], tuple[bool, float]] = {}  # (user id, project id) -> (Developer or higher, expiry)


def _forget_access(user_id: int):
    for key in [k for k in _access if k[0] == user_id]:
        _access.pop(key, None)


def _can_view_project(user: User, project_id: int, gl: GitLabClient | None = None) -> bool:
    """Whether the user is at least Developer on the project in GitLab (cached for a few minutes)."""
    key, now = (user.id, project_id), time.monotonic()
    hit = _access.get(key)
    if hit and hit[1] > now:
        return hit[0]
    try:
        if gl:
            ok = GitLabClient.access_level(gl.project(project_id)) >= DEVELOPER
        else:
            with gitlab_for(user) as own:
                ok = GitLabClient.access_level(own.project(project_id)) >= DEVELOPER
    except GitLabError:
        ok = False
    _access[key] = (ok, now + ACCESS_TTL)
    return ok


def _job_for(job_id: int, user: User, db: Session, act: bool = False) -> AnalysisJob:
    """The analysis, if the user may see it: their own, any for administrators, and other users' analyses of projects
    where they are at least Developer. Only the user who started an analysis can act on it (act=True)."""
    job = db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404, "That analysis doesn't exist.")
    if job.user_id == user.id:
        return job
    if not user.is_admin and not _can_view_project(user, job.project_id):
        raise HTTPException(404, "That analysis doesn't exist.")
    if act:
        raise HTTPException(403, f"Only {job.user.username} can act on this analysis. "
                                 "You can view it and download the report.")
    return job


@app.post("/api/jobs")
def create_job(body: JobIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request)
    if not re.fullmatch(r"[0-9a-f]{7,64}", body.sha):
        raise HTTPException(400, "That isn't a commit SHA.")
    picked = {s.strip().lower() for s in body.severities}
    if not picked:
        raise HTTPException(400, "Pick at least one severity.")
    if picked - set(SEVERITIES):
        raise HTTPException(400, f"Unknown severity: {', '.join(sorted(picked - set(SEVERITIES)))}.")
    severities = [s for s in SEVERITIES if s in picked]
    if body.thinking not in (None, "on", "off"):
        raise HTTPException(400, "Thinking must be on or off.")
    thinking = body.thinking or ("on" if llm_config(db)["thinking"] else "off")
    with gitlab_for(user) as gl:
        project = gl.project(body.project_id)  # also checks the user can see it
        scan = gl.scan_status(body.project_id, body.sha)
    if scan["state"] != "finished":
        raise HTTPException(409, f"Pick a commit whose SAST scan has finished ({scan['label']}).")
    running = db.scalar(select(AnalysisJob).where(AnalysisJob.project_id == body.project_id,
                                                  AnalysisJob.sha == body.sha,
                                                  func.coalesce(AnalysisJob.thinking, "on") == thinking,
                                                  AnalysisJob.status.in_(["queued", "running"])))
    if running:
        return {"id": running.id, "existing": True}
    job = AnalysisJob(user_id=user.id, project_id=body.project_id, project_path=project["path_with_namespace"],
                      branch=body.branch, sha=body.sha, default_branch=project.get("default_branch") or "",
                      severities=severities, thinking=thinking, progress="Waiting for a free worker")
    db.add(job)
    db.commit()
    return {"id": job.id, "existing": False}


def finding_json(f: Finding, job: AnalysisJob) -> dict:
    out = {k: getattr(f, k) for k in (
        "id", "uuid", "vulnerability_gid", "title", "severity", "scanner", "identifiers", "cwe", "file",
        "start_line", "end_line", "description", "code_flows", "status", "verdict", "confidence", "votes",
        "reasoning", "evidence", "fix", "diff", "validation_status", "validation_log", "injection_suspected",
        "context_files", "context_tokens", "error", "actions", "copied_from", "duration_s", "completion_tokens")}
    posted = prompts.posted_note(f)
    out["posted"] = posted and {k: posted.get(k) for k in ("url", "by", "at", "issue_iid", "copied_from_job")}
    out["gitlab_url"] = prompts.vulnerability_url(f, job, settings.gitlab_url)
    return out


@app.get("/api/jobs/{job_id}")
def get_job(job_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    job = _job_for(job_id, user, db)
    return {"id": job.id, "project_path": job.project_path, "project_id": job.project_id, "branch": job.branch,
            "sha": job.sha, "default_branch": job.default_branch, "status": job.status, "progress": job.progress,
            "error": job.error, "by": job.user.username, "can_act": job.user_id == user.id,
            "gitlab_url": settings.gitlab_url,
            "severities": job.severities, "thinking": job.thinking or "on",
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "findings": [finding_json(f, job) for f in job.findings]}


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request)
    job = _job_for(job_id, user, db, act=True)
    if job.status in ("queued", "running"):
        job.status, job.finished_at = "cancelled", utcnow()
        db.commit()
    return {"status": job.status}


@app.post("/api/jobs/{job_id}/rerun")
def rerun_job(job_id: int, request: Request, body: RerunIn | None = None, user: User = Depends(current_user),
              db: Session = Depends(get_db)):
    """A new analysis of the same commit; thinking on/off as the old one unless the body picks the other mode."""
    check_csrf(request)
    old = _job_for(job_id, user, db)
    thinking = (body and body.thinking) or old.thinking or "on"
    return create_job(JobIn(project_id=old.project_id, project_path=old.project_path, branch=old.branch,
                            sha=old.sha, severities=old.severities or SEVERITIES, thinking=thinking), request, user, db)


@app.post("/api/jobs/{job_id}/retry-failed")
def retry_failed(job_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Analyzes this job's failed findings again; everything else in the job (results, posts, saved votes) stays."""
    check_csrf(request)
    job = _job_for(job_id, user, db, act=True)
    if job.status in ("queued", "running"):
        raise HTTPException(409, "This analysis is still running.")
    failed = [f for f in job.findings if f.status == "error"]
    if not failed:
        raise HTTPException(409, "This analysis has no failed findings.")
    for f in failed:
        f.status, f.error = "pending", None
    job.status, job.finished_at, job.error = "queued", None, None
    job.progress = f"Queued to retry {len(failed)} failed finding{'' if len(failed) == 1 else 's'}"
    db.commit()
    log.info("%s retries %s failed findings of job %s", user.username, len(failed), job.id)
    return {"status": job.status, "retried": len(failed)}


# ------------------------------------------------------------------ API: write-back (uses the acting user's token)
def _finding_for(fid: int, user: User, db: Session, act: bool = False) -> Finding:
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, "That finding doesn't exist.")
    _job_for(f.job_id, user, db, act)
    return f


def _record(f: Finding, user: User, what: str, url: str | None, db: Session, **extra):
    f.actions = [*(f.actions or []),
                 {"type": what, "url": url, "by": user.username, "at": utcnow().isoformat(), **extra}]
    db.commit()


@app.post("/api/findings/{fid}/note")
def post_note(fid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Comments the analysis on the finding's issue, creating (and self-assigning) the issue if there is none.
    Each finding's analysis is posted once; the row lock stops two quick clicks from both posting."""
    check_csrf(request)
    _finding_for(fid, user, db, act=True)
    f = db.get(Finding, fid, with_for_update=True, populate_existing=True)
    posted = prompts.posted_note(f)
    if posted:
        on = f" on issue #{posted['issue_iid']}" if posted.get("issue_iid") else ""
        src = f" from analysis #{posted['copied_from_job']}" if posted.get("copied_from_job") else ""
        raise HTTPException(409, f"The analysis was already posted{on}{src} by {posted.get('by')} "
                                 f"on {str(posted.get('at', ''))[:10]}.")
    job = f.job
    with gitlab_for(user) as gl:
        issue = gl.find_finding_issue(job.project_id, f.uuid, f.vulnerability_gid)
        created = issue is None
        if created:
            issue = gl.create_finding_issue(
                job.project_id, prompts.issue_title(f),
                prompts.issue_markdown(f, job, settings.gitlab_url, gl.issue_marker(f.uuid)), f.vulnerability_gid)
        note = gl.issue_note(issue["project_id"], issue["iid"], prompts.note_markdown(f))
    url = f"{issue['web_url']}#note_{note['id']}" if note.get("id") else issue["web_url"]
    where = f"new issue #{issue['iid']} (assigned to you)" if created else f"issue #{issue['iid']}"
    _record(f, user, f"analysis posted on {where}", url, db, kind="note", issue_iid=issue["iid"])
    return {"ok": True, "url": url, "where": where, "issue_iid": issue["iid"], "created": created}


@app.post("/api/findings/{fid}/dismiss")
def dismiss(fid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request)
    f = _finding_for(fid, user, db, act=True)
    if not f.vulnerability_gid:
        raise HTTPException(409, "This finding has no vulnerability record yet (it isn't on the default branch). "
                                 "Post the analysis instead.")
    comment = f"False positive (confirmed by {user.username} after automated triage): {f.reasoning[:3500]}"
    with gitlab_for(user) as gl:
        gl.dismiss_vulnerability(f.vulnerability_gid, comment)
    _record(f, user, "dismissed as false positive", None, db)
    return {"ok": True}


@app.post("/api/findings/{fid}/mr")
def open_fix_mr(fid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    check_csrf(request)
    f = _finding_for(fid, user, db, act=True)
    if not f.fix or not f.fix.get("edits"):
        raise HTTPException(409, "This finding has no proposed fix.")
    job = f.job
    with gitlab_for(user) as gl:
        originals = {e["file"]: gl.file_raw(job.project_id, e["file"], job.sha) for e in f.fix["edits"]}
        try:
            changed = apply_edits(originals, f.fix["edits"])
        except EditError as exc:
            raise HTTPException(409, str(exc)) from exc
        branch = f"vuln-fix/{job.sha[:8]}-{f.id}-{secrets.token_hex(2)}"
        title = f"Fix {f.title[:120]} in {f.file}"
        mr = gl.create_fix_mr(job.project_id, job.sha, job.branch, branch, changed, title, prompts.note_markdown(f))
    _record(f, user, f"fix merge request !{mr['iid']}", mr["web_url"], db)
    return {"ok": True, "url": mr["web_url"], "iid": mr["iid"]}
