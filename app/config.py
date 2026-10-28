"""Configuration, read from environment variables (or a .env file loaded by the launcher).

Everything here works offline: no setting points at an internet host.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # Where the app keeps its database, secret key and repository checkouts.
    data_dir: Path = Path(os.getenv("VT_DATA_DIR", "./data")).resolve()
    database_url: str = os.getenv("VT_DATABASE_URL", "")

    # Self-hosted GitLab. Users store their own token in Settings; this is only the base URL.
    gitlab_url: str = os.getenv("VT_GITLAB_URL", "https://gitlab.internal").rstrip("/")
    # Path to the internal CA bundle, or "false" to disable TLS verification (not recommended).
    ca_bundle: str = os.getenv("VT_CA_BUNDLE", "")
    # "Sign in with GitLab": the OAuth application registered in GitLab (also settable on the Admin page).
    gitlab_oauth_id: str = os.getenv("VT_GITLAB_OAUTH_ID", "")
    gitlab_oauth_secret: str = os.getenv("VT_GITLAB_OAUTH_SECRET", "")
    # This app's address as users open it, e.g. https://securefix.internal. Empty: taken from each request.
    public_url: str = os.getenv("VT_PUBLIC_URL", "").rstrip("/")

    # Local vLLM server (OpenAI-compatible API).
    llm_base_url: str = os.getenv("VT_LLM_BASE_URL", "http://vllm.internal:8000/v1").rstrip("/")
    llm_model: str = os.getenv("VT_LLM_MODEL", "local-model")
    llm_api_key: str = os.getenv("VT_LLM_API_KEY", "EMPTY")
    llm_timeout_s: int = int(os.getenv("VT_LLM_TIMEOUT_S", "900"))
    # Model requests one analysis sends at the same time (vLLM batches them). 1 = one after another.
    llm_parallel: int = int(os.getenv("VT_LLM_PARALLEL", "4"))
    # Longest reply (in tokens) a triage request may get. A reply cut off at this limit is retried with twice as many.
    llm_max_tokens: int = int(os.getenv("VT_LLM_MAX_TOKENS", "4096"))
    # Use vLLM structured outputs (response_format json_schema). Turn off for older vLLM builds.
    llm_structured_output: bool = _bool("VT_LLM_STRUCTURED_OUTPUT", True)
    # Default for new analyses: let the model think before answering (Qwen3 enable_thinking). Slower, often more
    # careful; users can pick per analysis.
    llm_thinking: bool = _bool("VT_LLM_THINKING", True)
    # Local path or name of the model's tokenizer (optional; falls back to a char estimate).
    tokenizer_path: str = os.getenv("VT_TOKENIZER_PATH", "")

    # Analysis behaviour.
    context_token_budget: int = int(os.getenv("VT_CONTEXT_TOKEN_BUDGET", "100000"))
    triage_votes: int = int(os.getenv("VT_TRIAGE_VOTES", "3"))
    triage_temperature: float = float(os.getenv("VT_TRIAGE_TEMPERATURE", "0.4"))
    worker_threads: int = int(os.getenv("VT_WORKER_THREADS", "2"))
    validation_timeout_s: int = int(os.getenv("VT_VALIDATION_TIMEOUT_S", "900"))
    # Optional local CWE catalogue (MITRE cwec_*.xml) copied into the air gap.
    cwe_xml_path: str = os.getenv("VT_CWE_XML", "")

    # Web.
    session_cookie_secure: bool = _bool("VT_COOKIE_SECURE", True)

    checkouts_dir: Path = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "checkouts_dir", self.data_dir / "checkouts")

    @property
    def db_url(self) -> str:
        return self.database_url or f"sqlite:///{self.data_dir / 'vulntriage.db'}"

    @property
    def tls_verify(self):
        if self.ca_bundle.lower() == "false":
            return False
        return self.ca_bundle or True


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
settings.checkouts_dir.mkdir(parents=True, exist_ok=True)
