"""Client for the local vLLM server (OpenAI-compatible /v1/chat/completions)."""
import json
import logging
import re
import threading
from functools import lru_cache

import httpx
from sqlalchemy.orm import Session

from . import app_settings
from .config import settings
from .db import SessionLocal
from .security import decrypt_token, encrypt_token

log = logging.getLogger(__name__)


class LLMError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class BadReply(LLMError):
    """vLLM answered, but not with usable JSON (e.g. the reply was cut off at the token limit)."""


MAX_TOKENS_RANGE = (1024, 32768)
RETRY_TOKENS_CAP = 16384  # a reply cut off at the limit is retried with up to this many tokens
SHORTER = ("\n\nYour previous answer was too long and was cut off. Answer again with the same JSON object, "
           "keeping every text field short (reasoning under 150 words).")


# ---------------------------------------------------------------- settings (.env defaults, admin overrides)
def _env_defaults() -> dict:
    return {"base_url": settings.llm_base_url, "model": settings.llm_model, "api_key": settings.llm_api_key,
            "structured_output": settings.llm_structured_output, "timeout_s": settings.llm_timeout_s,
            "parallel": settings.llm_parallel, "max_tokens": settings.llm_max_tokens, "thinking": settings.llm_thinking}


def llm_overrides(db: Session) -> dict[str, str]:
    return app_settings.load(db, "llm")


def llm_config(db: Session | None = None) -> dict:
    """The vLLM settings in effect: what an administrator saved in the app, else the .env values."""
    if db is None:
        with SessionLocal() as own:
            return llm_config(own)
    cfg = _env_defaults()
    saved = llm_overrides(db)
    for key in ("base_url", "model"):
        if saved.get(key):
            cfg[key] = saved[key]
    if saved.get("api_key"):
        try:
            cfg["api_key"] = decrypt_token(saved["api_key"])
        except ValueError:
            log.warning("Saved vLLM API key can't be decrypted (secret key changed); using the .env key.")
    if "structured_output" in saved:
        cfg["structured_output"] = saved["structured_output"] == "true"
    if "thinking" in saved:
        cfg["thinking"] = saved["thinking"] == "true"
    if saved.get("timeout_s", "").isdigit():
        cfg["timeout_s"] = int(saved["timeout_s"])
    if saved.get("parallel", "").isdigit():
        cfg["parallel"] = int(saved["parallel"])
    cfg["parallel"] = min(max(cfg["parallel"], 1), 32)
    if saved.get("max_tokens", "").isdigit():
        cfg["max_tokens"] = int(saved["max_tokens"])
    cfg["max_tokens"] = min(max(cfg["max_tokens"], MAX_TOKENS_RANGE[0]), MAX_TOKENS_RANGE[1])
    return cfg


def save_llm_config(db: Session, base_url: str, model: str, structured_output: bool, timeout_s: int,
                    api_key: str | None = None, parallel: int | None = None, max_tokens: int | None = None,
                    thinking: bool | None = None):
    """api_key None keeps the saved key; any string (EMPTY for none) replaces it."""
    values = {"base_url": base_url, "model": model, "structured_output": "true" if structured_output else "false",
              "timeout_s": str(timeout_s)}
    if parallel is not None:
        values["parallel"] = str(parallel)
    if max_tokens is not None:
        values["max_tokens"] = str(max_tokens)
    if thinking is not None:
        values["thinking"] = "true" if thinking else "false"
    if api_key is not None:
        values["api_key"] = encrypt_token(api_key)
    app_settings.save(db, "llm", values)


def reset_llm_config(db: Session):
    app_settings.clear(db, "llm")


@lru_cache(maxsize=1)
def _tokenizer():
    if not settings.tokenizer_path:
        return None
    try:
        from transformers import AutoTokenizer  # optional dependency
        return AutoTokenizer.from_pretrained(settings.tokenizer_path, local_files_only=True)
    except Exception as exc:  # noqa: BLE001 - fall back to estimation
        log.warning("Tokenizer unavailable (%s); estimating tokens from characters.", exc)
        return None


def count_tokens(text: str) -> int:
    tok = _tokenizer()
    if tok is not None:
        return len(tok.encode(text, add_special_tokens=False))
    return int(len(text) / 3.2) + 1  # conservative for code


def _extract_json(text: str) -> dict:
    # Reasoning models put their thinking before the answer when vLLM runs without a reasoning parser; Qwen3 sends
    # an empty <think></think> when thinking is off. A reply cut off while thinking has no closing tag.
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    text = re.sub(r"^\s*<think>.*", "", text, flags=re.S)
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
        raise


class LLMClient:
    def __init__(self, thinking: bool | None = None):
        # Read once per client: a job keeps the settings it started with. thinking overrides the default per job.
        self.cfg = llm_config()
        if thinking is not None:
            self.cfg["thinking"] = thinking
        self.http = httpx.Client(base_url=self.cfg["base_url"], timeout=self.cfg["timeout_s"],
                                 headers={"Authorization": f"Bearer {self.cfg['api_key']}"})
        # Requests this client (one job) may have open at once; held only around the HTTP call.
        self._slots = threading.BoundedSemaphore(self.cfg["parallel"])

    def health(self) -> dict:
        model = self.cfg["model"]
        try:
            r = self.http.get("/models", timeout=10)
            r.raise_for_status()
            models = [m["id"] for m in r.json().get("data", [])]
            return {"ok": model in models, "models": models,
                    "detail": "" if model in models else f"Model {model} isn't served."}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "models": [], "detail": f"Can't reach vLLM at {self.cfg['base_url']}: {exc}"}

    def _post(self, messages: list, schema: dict, name: str, temperature: float, max_tokens: int,
              usage: list | None = None) -> tuple[str, bool]:
        """One request; returns (reply text, whether it was cut off at max_tokens). Appends the tokens the model
        generated (thinking included) to usage."""
        body = {"model": self.cfg["model"], "messages": messages, "temperature": temperature,
                "max_tokens": max_tokens,
                # Qwen3's chat template switches its thinking with this; templates without it ignore it.
                "chat_template_kwargs": {"enable_thinking": bool(self.cfg["thinking"])}}
        if self.cfg["structured_output"]:
            body["response_format"] = {"type": "json_schema",
                                       "json_schema": {"name": name, "schema": schema, "strict": True}}
        try:
            with self._slots:
                r = self.http.post("/chat/completions", json=body)
        except httpx.HTTPError as exc:
            raise LLMError(f"Can't reach vLLM: {exc}") from exc
        if r.status_code >= 400:
            raise LLMError(f"vLLM returned {r.status_code}: {r.text[:500]}", r.status_code)
        reply = r.json()
        if usage is not None:
            usage.append((reply.get("usage") or {}).get("completion_tokens") or 0)
        choice = reply["choices"][0]
        return choice["message"].get("content") or "", choice.get("finish_reason") == "length"

    def chat_json(self, system: str, user: str, schema: dict, name: str,
                  temperature: float = 0.0, max_tokens: int | None = None,
                  usage: list | None = None) -> tuple[dict, str]:
        """Returns (parsed JSON, raw text). Retries once if the reply isn't valid JSON: a reply cut off at the token
        limit is asked again with a larger limit and a request to be brief, anything else is asked for only the JSON."""
        tokens = max_tokens or self.cfg["max_tokens"]
        first = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        raw, cut = self._post(first, schema, name, temperature, tokens, usage)
        try:
            return _extract_json(raw), raw
        except (json.JSONDecodeError, ValueError) as exc:
            err = exc
        if cut:
            log.info("Model reply cut off at %s tokens; retrying with a larger limit", tokens)
            short = [first[0], {"role": "user", "content": user + SHORTER}]
            bigger = max(tokens, min(tokens * 2, RETRY_TOKENS_CAP))
            try:
                raw, cut = self._post(short, schema, name, temperature, bigger, usage)
            except LLMError as exc:
                if exc.status != 400 or bigger == tokens:
                    raise
                # Most likely the prompt plus the larger reply exceed the model's context: keep the old limit.
                bigger = tokens
                raw, cut = self._post(short, schema, name, temperature, tokens, usage)
            try:
                return _extract_json(raw), raw
            except (json.JSONDecodeError, ValueError) as exc:
                if cut:
                    raise BadReply(f"Model reply was cut off at {bigger} tokens, even when asked to be brief. "
                                   "Raise Max tokens on the Admin page, then retry the failed findings.") from exc
                err = exc
        else:
            raw2, _ = self._post(first + [{"role": "assistant", "content": raw},
                                          {"role": "user", "content": "Reply with only the JSON object."}],
                                 schema, name, temperature, tokens, usage)
            try:
                return _extract_json(raw2), raw2
            except (json.JSONDecodeError, ValueError) as exc:
                err = exc
        raise BadReply(f"Model reply wasn't valid JSON: {err}")

    def close(self):
        self.http.close()
