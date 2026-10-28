"""SQLAlchemy models. SQLite by default; set VT_DATABASE_URL for Postgres in multi-instance setups."""
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
                        create_engine, event, inspect, text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import settings


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(200))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    gitlab_token_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "access_token": personal/project/group access token (PRIVATE-TOKEN header).
    # "oauth": OAuth access token (Authorization: Bearer).
    gitlab_token_type: Mapped[str] = mapped_column(String(20), default="access_token")
    gitlab_username: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Set by "Sign in with GitLab": the GitLab account, and the refresh token that renews the OAuth access token.
    gitlab_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    gitlab_refresh_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    gitlab_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # "local": password kept here. "ldap": Windows (Active Directory) account; the directory checks the password.
    # "gitlab": signs in with GitLab only.
    auth_source: Mapped[str] = mapped_column(String(20), default="local")
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    email: Mapped[str | None] = mapped_column(String(200), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def is_windows(self) -> bool:
        return self.auth_source == "ldap"

    @property
    def is_gitlab(self) -> bool:
        return self.auth_source == "gitlab"

    @property
    def has_password(self) -> bool:
        return self.auth_source == "local"

    @property
    def initials(self) -> str:
        words = (self.display_name or self.username).replace(".", " ").replace("_", " ").replace("-", " ").split()
        return ((words[0][0] + words[1][0]) if len(words) > 1 else words[0][:2]).upper() if words else "?"


class ProjectConfig(Base):
    """Per-project commands the patch validator runs. Shared by all users of that project."""
    __tablename__ = "project_configs"
    id: Mapped[int] = mapped_column(primary_key=True)
    gitlab_project_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    build_cmd: Mapped[str] = mapped_column(Text, default="")
    test_cmd: Mapped[str] = mapped_column(Text, default="")
    rescan_cmd: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AppSetting(Base):
    """Settings administrators change in the app; they override the matching .env defaults."""
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class AnalysisJob(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    project_id: Mapped[int] = mapped_column(Integer, index=True)
    project_path: Mapped[str] = mapped_column(String(500))
    branch: Mapped[str] = mapped_column(String(500))
    sha: Mapped[str] = mapped_column(String(64), index=True)
    default_branch: Mapped[str] = mapped_column(String(500), default="")
    pipeline_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severities: Mapped[list | None] = mapped_column(JSON, nullable=True)  # severities to analyze; None = all
    thinking: Mapped[str | None] = mapped_column(String(10), nullable=True)  # on|off; None (older analyses) = on
    context_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)  # tokens of code per finding; None = .env
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)  # queued|running|done|failed|cancelled
    progress: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    findings: Mapped[list["Finding"]] = relationship(back_populates="job", cascade="all, delete-orphan",
                                                     order_by="Finding.id")
    user: Mapped[User] = relationship()

    @property
    def budget(self) -> int:
        """Tokens of code per finding this analysis used (older analyses used the .env value)."""
        return self.context_budget or settings.context_token_budget


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), index=True)
    uuid: Mapped[str] = mapped_column(String(100), index=True)
    vulnerability_gid: Mapped[str | None] = mapped_column(String(200), nullable=True)
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="unknown")
    scanner: Mapped[str] = mapped_column(String(200), default="")
    identifiers: Mapped[list] = mapped_column(JSON, default=list)
    cwe: Mapped[str] = mapped_column(String(40), default="")
    file: Mapped[str] = mapped_column(Text, default="")
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    code_flows: Mapped[list] = mapped_column(JSON, default=list)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)

    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|analyzing|done|error|skipped
    verdict: Mapped[str | None] = mapped_column(String(30), nullable=True)  # true_positive|false_positive|needs_review
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    votes: Mapped[list] = mapped_column(JSON, default=list)
    reasoning: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    fix: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # {edits, explanation, suggested_test}
    diff: Mapped[str] = mapped_column(Text, default="")
    validation_status: Mapped[str | None] = mapped_column(String(30), nullable=True)  # passed|failed|not_configured|skipped
    validation_log: Mapped[str] = mapped_column(Text, default="")
    injection_suspected: Mapped[bool] = mapped_column(Boolean, default=False)
    context_files: Mapped[list] = mapped_column(JSON, default=list)
    context_tokens: Mapped[int] = mapped_column(Integer, default=0)
    duration_s: Mapped[float | None] = mapped_column(Float, nullable=True)  # wall-clock time spent analyzing it
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)  # tokens the model generated for it
    cache_key: Mapped[str] = mapped_column(String(100), default="", index=True)
    # Same vulnerability, file, lines and code (see analyzer.code_key): a later commit copies this analysis.
    code_key: Mapped[str] = mapped_column(String(64), default="", index=True)
    copied_from: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # {finding, job, sha, at, why}
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    actions: Mapped[list] = mapped_column(JSON, default=list)  # audit of write-backs: [{type, url, by, at}]
    llm_log: Mapped[list] = mapped_column(JSON, default=list)  # prompts and raw responses, for audit
    job: Mapped[AnalysisJob] = relationship(back_populates="findings")


_connect_args = {"check_same_thread": False, "timeout": 30} if settings.db_url.startswith("sqlite") else {}
engine = create_engine(settings.db_url, connect_args=_connect_args, pool_pre_ping=True)

if settings.db_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")  # readers don't block the worker's writes
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


# Columns added after the first release. create_all doesn't touch existing tables, so init_db adds them.
_ADDED_COLUMNS = {
    "jobs": {"severities": "JSON", "thinking": "VARCHAR(10)", "context_budget": "INTEGER"},
    "findings": {"code_key": "VARCHAR(64) NOT NULL DEFAULT ''", "copied_from": "JSON", "duration_s": "FLOAT",
                 "completion_tokens": "INTEGER"},
    "users": {"auth_source": "VARCHAR(20) NOT NULL DEFAULT 'local'", "display_name": "VARCHAR(200)",
              "email": "VARCHAR(200)", "last_login_at": "TIMESTAMP WITH TIME ZONE", "gitlab_user_id": "INTEGER",
              "gitlab_refresh_enc": "TEXT", "gitlab_token_expires_at": "TIMESTAMP WITH TIME ZONE"},
}


def init_db():
    Base.metadata.create_all(engine)
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, wanted in _ADDED_COLUMNS.items():
            have = {c["name"] for c in insp.get_columns(table)}
            for column, ddl in wanted.items():
                if column not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_findings_code_key ON findings (code_key)"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
