"""Runs one analysis job: pull the commit's SAST findings, check out the code, then triage and fix
each finding."""
import hashlib
import logging
import shutil
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path

from sqlalchemy import func, select

from . import prompts
from .config import settings
from .context_builder import ContextBuilder, read_lines
from .db import AnalysisJob, Finding, ProjectConfig, SessionLocal, User, utcnow
from .gitlab_client import GitLabClient, GitLabError
from .llm_client import BadReply, LLMClient, LLMError
from .patcher import EditError, apply_edits, unified_diff, validate
from .security import decrypt_token

log = logging.getLogger(__name__)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SEVERITIES = list(SEVERITY_ORDER)
DEFAULT_SEVERITIES = ["critical", "high"]  # what a new analysis covers unless the user picks others


class JobCancelled(Exception):
    pass


# ---------------------------------------------------------------- CWE catalogue (optional, offline)
COPY_WINDOW = 10  # lines around the finding that must be unchanged for a later commit to copy its analysis


def code_key(f: Finding, project_id: int, read) -> str:
    """Identifies a finding by what the analysis depends on most: the vulnerability, its file and lines, the code on
    and around those lines, and the code at each step of the scanner's taint trace. read(path) returns the file's
    lines at the finding's commit, or None. Empty when the finding has no line or its file can't be read."""
    lines = read(f.file) if f.file and f.start_line else None
    if not lines:
        return ""
    start, end = f.start_line, f.end_line or f.start_line
    parts = [str(project_id), f.scanner, f.title, f.cwe, f.file, str(start), str(end), "--",
             *lines[max(0, start - 1 - COPY_WINDOW):end + COPY_WINDOW]]
    for step in (f.code_flows or [])[:30]:
        step_lines = read(step["file"]) or []
        line = int(step.get("line") or 0)
        parts += ["--", f"{step['file']}:{line}", *step_lines[max(0, line - 4):line + 3]]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


COPIED_FIELDS = ("verdict", "confidence", "votes", "reasoning", "evidence", "fix", "diff", "validation_status",
                 "validation_log", "injection_suspected", "context_files", "context_tokens")


@lru_cache(maxsize=1)
def _cwe_catalogue() -> dict[str, str]:
    if not settings.cwe_xml_path or not Path(settings.cwe_xml_path).exists():
        return {}
    out = {}
    for _, el in ET.iterparse(settings.cwe_xml_path):
        if el.tag.endswith("Weakness") and el.get("ID"):
            desc = next((c.text for c in el if c.tag.endswith("Description")), "") or ""
            out[el.get("ID")] = f"CWE-{el.get('ID')} {el.get('Name')}: {desc.strip()}"
            el.clear()
    return out


def cwe_text(cwe: str) -> str:
    return _cwe_catalogue().get(cwe.removeprefix("CWE-"), "") if cwe else ""


# ---------------------------------------------------------------- report parsing
def _code_flow_steps(details) -> list[dict]:
    """Collects file/line steps from Advanced SAST code flows, whatever the exact nesting."""
    steps = []

    def walk(node):
        if isinstance(node, dict):
            loc = node.get("file_location") if isinstance(node.get("file_location"), dict) else node
            fname = loc.get("file_name") or loc.get("file")
            line = loc.get("line_start") or loc.get("start_line")
            if fname and isinstance(line, int):
                steps.append({"file": fname, "line": line, "kind": node.get("node_type", "step")})
                return
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    if isinstance(details, dict):
        walk(details.get("code_flows") or details.get("codeFlows") or {})
    seen, out = set(), []
    for s in steps:
        key = (s["file"], s["line"])
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def parse_report(report: dict) -> list[dict]:
    scanner = ((report.get("scan") or {}).get("analyzer") or (report.get("scan") or {}).get("scanner") or {}).get("name", "")
    out = []
    for v in report.get("vulnerabilities") or []:
        loc = v.get("location") or {}
        idents = v.get("identifiers") or []
        cwe = next((f"CWE-{i.get('value')}" for i in idents if (i.get("type") or "").lower() == "cwe"), "")
        out.append({
            "report_id": v.get("id") or v.get("cve") or "",
            "title": v.get("name") or v.get("message") or "Untitled finding",
            "severity": (v.get("severity") or "unknown").lower(),
            "scanner": (v.get("scanner") or {}).get("name") or scanner,
            "identifiers": [{"type": i.get("type"), "name": i.get("name"), "value": i.get("value")} for i in idents],
            "cwe": cwe,
            "file": loc.get("file", ""),
            "start_line": loc.get("start_line"),
            "end_line": loc.get("end_line"),
            "description": v.get("description") or "",
            "code_flows": _code_flow_steps(v.get("details")),
            "raw": v,
        })
    return out


def _merge_gitlab_findings(parsed: list[dict], gl_findings: list[dict]) -> None:
    """Attach GitLab's finding UUID, state and vulnerability ID, matched on location + primary identifier."""
    by_loc = {}
    for g in gl_findings:
        loc = g.get("location") or {}
        key = (loc.get("file"), int(loc["startLine"]) if loc.get("startLine") else None)
        by_loc.setdefault(key, []).append(g)
    for p in parsed:
        candidates = by_loc.get((p["file"], p["start_line"]), [])
        match = None
        names = {i["name"] for i in p["identifiers"]}
        for g in candidates:
            if g.get("uuid") == p["report_id"] or names & {i.get("name") for i in g.get("identifiers") or []}:
                match = g
                break
        match = match or (candidates[0] if len(candidates) == 1 else None)
        if match:
            p["uuid"] = match.get("uuid") or p["report_id"]
            p["state"] = (match.get("state") or "").lower()
            vuln = match.get("vulnerability") or {}
            p["vulnerability_gid"] = vuln.get("id")
            if vuln.get("state"):
                p["state"] = vuln["state"].lower()


# ---------------------------------------------------------------- job runner
class JobRunner:
    def __init__(self, job_id: int):
        self.job_id = job_id
        self.db = SessionLocal()
        self.job: AnalysisJob = self.db.get(AnalysisJob, job_id)
        user: User = self.db.get(User, self.job.user_id)
        if not user.gitlab_token_enc:
            raise GitLabError("The user who started this analysis has no GitLab token in Settings.")
        self.gl = GitLabClient(decrypt_token(user.gitlab_token_enc), user.gitlab_token_type)
        self.thinking = self.job.thinking or "on"  # analyses from before the choice ran with the model's default
        self.llm = LLMClient(thinking=self.thinking == "on")
        self.budget = self.job.budget
        self.workdir = settings.checkouts_dir / f"job-{job_id}"
        cfg = self.db.scalar(select(ProjectConfig).where(ProjectConfig.gitlab_project_id == self.job.project_id))
        if cfg is not None:
            self.db.expunge(cfg)  # a read-only snapshot: finding threads read it without touching self.db
        self.cfg = cfg or ProjectConfig(gitlab_project_id=self.job.project_id)
        # Findings are analyzed in parallel threads (see _analyze_one); self.db and the counters belong to the
        # job and are only touched under _lock, validation runs one at a time, and _stop ends every thread.
        self._lock = threading.RLock()
        self._validate_lock = threading.Lock()
        self._stop = threading.Event()
        self._total = self._done = self._active = 0
        self._old_files: dict[tuple[str, str], list[str] | None] = {}  # (sha, path) -> lines, for code_key

    def check_cancelled(self):
        """Raises JobCancelled once the user cancels; checked before each model request and each finding."""
        with self._lock:
            if not self._stop.is_set():
                self.db.refresh(self.job, ["status"])
                if self.job.status == "cancelled":
                    self._stop.set()
            if self._stop.is_set():
                raise JobCancelled()

    def progress(self, text: str):
        with self._lock:
            self.check_cancelled()
            self.job.progress = text
            self.db.commit()

    def run(self):
        try:
            self._run()
            self.job.status = "done"
            self.job.progress = "Finished"
        except JobCancelled:
            self.job.progress = "Cancelled"
        except (GitLabError, LLMError, ValueError) as exc:
            self.job.status, self.job.error = "failed", str(exc)
        except Exception as exc:  # noqa: BLE001 - surface anything unexpected to the user
            log.exception("Job %s crashed", self.job_id)
            self.job.status, self.job.error = "failed", f"Unexpected error: {exc}"
        finally:
            self.job.finished_at = utcnow()
            self.db.commit()
            shutil.rmtree(self.workdir, ignore_errors=True)
            self.gl.close()
            self.llm.close()
            self.db.close()

    def _run(self):
        job = self.job
        job.error = None
        self.db.commit()
        if job.findings:
            # Requeued after a restart or an upgrade: keep every finished finding and carry on with the rest.
            for f in job.findings:
                if f.status == "analyzing":
                    f.status = "pending"  # resumes from its saved model calls (see analyze)
            self.db.commit()
            finished = sum(f.status != "pending" for f in job.findings)
            log.info("Job %s resumes with %s of %s findings finished", job.id, finished, len(job.findings))
            self.progress(f"Resuming: {finished} of {len(job.findings)} findings were already finished")
        else:
            self._load_findings()
        if not any(f.status == "pending" for f in job.findings):
            return

        self.progress("Checking out the commit")
        project = self.gl.project(job.project_id)
        shutil.rmtree(self.workdir, ignore_errors=True)
        self.gl.checkout(project["http_url_to_repo"], job.sha, job.branch, self.workdir)

        pending = [f.id for f in job.findings if f.status == "pending"]
        self._total, self._done = len(job.findings), len(job.findings) - len(pending)
        workers = min(self.llm.cfg["parallel"], len(pending))
        if workers <= 1:
            for fid in pending:
                self._analyze_one(fid)
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=f"vt-job-{job.id}") as pool:
                list(pool.map(self._analyze_one, pending))
        self.db.expire_all()  # the threads saved the findings through their own sessions
        if self._stop.is_set():
            raise JobCancelled()

    def _analyze_one(self, fid: int):
        """Analyzes one finding in its own database session, so several findings can run at once."""
        if self._stop.is_set():
            return
        with SessionLocal() as db:
            f = db.get(Finding, fid)
            with self._lock:
                self._active += 1
            started = time.monotonic()
            try:
                self.progress(self._progress_text(f.title))
                self.analyze(f, db)
            except JobCancelled:
                f.status = "pending"  # Run again (or a restart) carries on from its saved model calls
            except Exception as exc:  # noqa: BLE001 - one bad finding mustn't stop the job
                log.exception("Finding %s failed", f.id)
                f.status, f.error = "error", str(exc)
            finally:
                # Accumulates over a resume or a retry; a copied analysis only records its own (short) time.
                f.duration_s = round((f.duration_s or 0) + time.monotonic() - started, 2)
                db.commit()
                with self._lock:
                    self._active -= 1
                    self._done += f.status != "pending"

    def _progress_text(self, title: str) -> str:
        with self._lock:
            if self._active > 1:
                return f"Analyzing findings: {self._done} of {self._total} done, {self._active} in progress"
            return f"Analyzing finding {self._done + 1} of {self._total}: {title[:80]}"

    def _load_findings(self):
        job = self.job
        self.progress("Looking up the commit's SAST scan")
        scan = self.gl.scan_status(job.project_id, job.sha)
        if scan["state"] != "finished":
            raise GitLabError(f"This commit's SAST scan isn't finished ({scan['label']}).")
        job.pipeline_id = scan["pipeline_id"]

        self.progress("Downloading the SAST report")
        parsed = []
        for j in scan["jobs"]:
            if j["status"] == "success":
                try:
                    parsed.extend(parse_report(self.gl.sast_report(job.project_id, j["id"])))
                except GitLabError as exc:
                    log.warning("No report from job %s: %s", j["id"], exc)
        try:
            _merge_gitlab_findings(parsed, self.gl.pipeline_security_findings(job.project_path, scan["pipeline_iid"]))
        except GitLabError as exc:
            log.warning("GraphQL findings unavailable, using report only: %s", exc)

        parsed.sort(key=lambda p: (SEVERITY_ORDER.get(p["severity"], 9), p["file"], p["start_line"] or 0))
        wanted = set(job.severities or SEVERITIES)  # jobs from before the severity choice analyzed everything
        for p in parsed:
            skip = ""
            if p.get("state") in {"dismissed", "resolved"}:
                skip = f"Skipped: already {p['state']} in GitLab."
            elif p["severity"] not in wanted:
                skip = f"Skipped: {p['severity']} severity wasn't selected for this analysis."
            job.findings.append(Finding(
                uuid=p.get("uuid") or p["report_id"] or hashlib.sha1(f"{p['file']}{p['start_line']}{p['title']}".encode()).hexdigest(),
                vulnerability_gid=p.get("vulnerability_gid"), title=p["title"], severity=p["severity"],
                scanner=p["scanner"], identifiers=p["identifiers"], cwe=p["cwe"], file=p["file"],
                start_line=p["start_line"], end_line=p["end_line"], description=p["description"],
                code_flows=p["code_flows"], raw=p["raw"], status="skipped" if skip else "pending",
                reasoning=skip))
        self.db.commit()

    # ---------------------------------------------------------------- copying earlier analyses
    def _old_lines(self, sha: str, path: str) -> list[str] | None:
        """A file at an earlier commit, from GitLab (the checkout only has this job's commit)."""
        key = (sha, path)
        if key not in self._old_files:
            try:
                self._old_files[key] = self.gl.file_raw(self.job.project_id, path, sha).splitlines()
            except GitLabError:
                self._old_files[key] = None
        return self._old_files[key]

    def _copy_earlier(self, f: Finding, db) -> bool:
        """Copies the latest finished analysis of the same vulnerability at the same lines with the same code from an
        earlier analysis of this project, so the model isn't asked again."""
        if not f.code_key:
            return False
        candidates = db.scalars(
            select(Finding).join(AnalysisJob, Finding.job_id == AnalysisJob.id)
            .where(Finding.code_key.in_((f.code_key, "")),  # "": analyzed before code keys existed
                   AnalysisJob.project_id == self.job.project_id, Finding.job_id != f.job_id,
                   func.coalesce(AnalysisJob.thinking, "on") == self.thinking,  # A/B runs must ask the model
                   func.coalesce(AnalysisJob.context_budget, settings.context_token_budget) == self.budget,
                   Finding.status == "done", Finding.verdict.is_not(None), Finding.context_tokens > 0,
                   Finding.file == f.file, Finding.start_line == f.start_line,
                   Finding.end_line.is_not_distinct_from(f.end_line), Finding.title == f.title,
                   Finding.cwe == f.cwe, Finding.scanner == f.scanner)
            .order_by(Finding.id.desc()).limit(5)).all()
        for old in candidates:
            if not old.code_key:  # analyzed before code keys existed: work it out from that commit's files
                old.code_key = code_key(old, self.job.project_id, lambda p, sha=old.job.sha: self._old_lines(sha, p))
                if not old.code_key:
                    old.code_key = "-"  # file gone at that commit: never matches, and isn't looked up again
            if old.code_key != f.code_key:
                continue
            for attr in COPIED_FIELDS:
                setattr(f, attr, getattr(old, attr))
            at = old.job.finished_at or old.job.created_at
            f.copied_from = {"finding": old.id, "job": old.job_id, "sha": old.job.sha,
                             "at": at.isoformat() if at else None, "why": "same vulnerability, lines and code"}
            f.llm_log = [{"note": f"Copied the analysis of finding #{old.id} (analysis #{old.job_id}, commit "
                                  f"{old.job.sha[:8]}): same vulnerability, file, lines and code."}]
            f.status = "done"
            return True
        return False

    # ---------------------------------------------------------------- per finding
    def analyze(self, f: Finding, db):
        f.status = "analyzing"
        db.commit()
        f.code_key = code_key(f, self.job.project_id, lambda p: read_lines(self.workdir, p))
        if self._copy_earlier(f, db):
            return
        ctx = ContextBuilder(self.workdir, self.budget).build(f)
        f.context_files, f.context_tokens, f.injection_suspected = ctx.files, ctx.tokens, ctx.injection_suspected
        if not ctx.chunks:
            f.status, f.verdict = "done", "needs_review"
            f.reasoning = f"The file {f.file} couldn't be read at this commit, so the finding wasn't analyzed."
            return

        f.cache_key = hashlib.sha256(
            f"{f.uuid}|{ctx.digest}|{self.llm.cfg['model']}|{prompts.PROMPT_VERSION}|thinking={self.thinking}"
            .encode()).hexdigest()
        cached = db.scalar(select(Finding).where(Finding.cache_key == f.cache_key, Finding.status == "done",
                                                      Finding.id != f.id).order_by(Finding.id.desc()))
        if cached:
            for attr in ("verdict", "confidence", "votes", "reasoning", "evidence", "fix", "diff",
                         "validation_status", "validation_log"):
                setattr(f, attr, getattr(cached, attr))
            f.llm_log = [{"note": f"Reused result of finding #{cached.id}: same code and prompt."}]
            at = cached.job.finished_at or cached.job.created_at
            f.copied_from = {"finding": cached.id, "job": cached.job_id, "sha": cached.job.sha,
                             "at": at.isoformat() if at else None, "why": "same code and prompt"}
            f.status = "done"
            return

        db.commit()  # don't hold the cache lookup's write open during the model requests (SQLite locks the file)
        block = prompts.finding_block(f, cwe_text(f.cwe))
        context = ctx.render()

        # Triage: several independent votes; any disagreement goes to a human. The votes are sent at once and each
        # is saved as soon as it arrives, so a job resumed after a restart reuses the votes it already has for the
        # same code and model.
        n_votes = max(1, settings.triage_votes)
        logs = [e for e in (f.llm_log or []) if e.get("call") == "triage" and e.get("key") == f.cache_key
                and isinstance(e.get("parsed"), dict)][:n_votes]
        votes = [e["parsed"] for e in logs]
        user_prompt = prompts.triage_user_prompt(block, context)
        temperature = settings.triage_temperature if n_votes > 1 else 0.0

        def vote():
            self.check_cancelled()
            usage = []
            res, raw = self.llm.chat_json(prompts.TRIAGE_SYSTEM, user_prompt, prompts.TRIAGE_SCHEMA, "triage",
                                          temperature=temperature, usage=usage)
            return res, raw, sum(usage)

        missing, failure = n_votes - len(votes), None
        if missing:
            with ThreadPoolExecutor(max_workers=missing) as pool:
                for fut in as_completed([pool.submit(vote) for _ in range(missing)]):
                    try:
                        res, raw, tokens = fut.result()
                    except BaseException as exc:  # noqa: BLE001 - save the votes that did arrive, then fail
                        failure = failure or exc
                        continue
                    votes.append(res)
                    logs.append({"call": "triage", "response": raw, "parsed": res, "key": f.cache_key,
                                 "tokens": tokens})
                    f.llm_log = list(logs)
                    db.commit()
        # A run whose reply was unreadable doesn't sink the finding if other runs answered; it only lowers confidence.
        if failure and (not votes or not isinstance(failure, BadReply)):
            raise failure
        if failure:
            logs.append({"call": "triage", "error": str(failure), "key": f.cache_key})
        counts = Counter(v.get("verdict") for v in votes)
        top, top_n = counts.most_common(1)[0]
        verdict = top if top_n == len(votes) else "needs_review"
        chosen = next(v for v in votes if v.get("verdict") == top)
        agreeing = [float(v.get("confidence") or 0) for v in votes if v.get("verdict") == top]
        f.verdict = verdict
        f.confidence = round(sum(agreeing) / len(agreeing) * top_n / n_votes, 3)
        f.votes = [{"verdict": v.get("verdict"), "confidence": v.get("confidence")} for v in votes]
        f.reasoning = chosen.get("reasoning", "")
        if verdict == "needs_review" and top_n != len(votes):
            f.reasoning = (f"The model's {len(votes)} triage runs disagreed "
                           f"({', '.join(f'{k}: {c}' for k, c in counts.items())}). Most common reading:\n\n" + f.reasoning)
        if len(votes) < n_votes:
            f.reasoning = (f"{n_votes - len(votes)} of the model's {n_votes} triage runs returned an unreadable reply; "
                           f"this is based on the other {len(votes)}.\n\n" + f.reasoning)
        f.evidence = chosen.get("evidence") or []
        if f.injection_suspected:
            f.evidence = ["Context contains text addressed to an AI or reviewer; check the verdict manually."] + f.evidence

        if verdict == "true_positive":
            self.check_cancelled()
            self.fix(f, block, context, chosen, logs)
        f.llm_log = logs
        f.completion_tokens = sum(e.get("tokens") or 0 for e in logs)
        f.status = "done"

    def fix(self, f: Finding, block: str, context: str, triage: dict, logs: list):
        error = ""
        for attempt in range(2):  # one retry with the validation output
            usage = []
            res, raw = self.llm.chat_json(prompts.FIX_SYSTEM, prompts.fix_user_prompt(block, context, triage, error),
                                          prompts.FIX_SCHEMA, "fix", temperature=0.0,
                                          max_tokens=max(8192, self.llm.cfg["max_tokens"]), usage=usage)
            logs.append({"call": f"fix attempt {attempt + 1}", "response": raw, "tokens": sum(usage)})
            f.fix = res
            originals = {}
            for e in res.get("edits") or []:
                lines = read_lines(self.workdir, e.get("file", ""))
                if lines is not None:
                    originals[e["file"]] = (self.workdir / e["file"]).read_text(encoding="utf-8", errors="replace")
            try:
                changed = apply_edits(originals, res.get("edits") or [])
                if not changed:
                    raise EditError("The proposed edits don't change any file.")
            except EditError as exc:
                error = str(exc)
                f.validation_status, f.validation_log, f.diff = "failed", f"Couldn't apply the fix: {exc}", ""
                continue
            f.diff = unified_diff(originals, changed)
            self.progress(f"Validating the fix for: {f.title[:80]}")
            with self._validate_lock:  # builds and tests run one at a time, even with parallel findings
                result = validate(self.workdir, changed, self.cfg.build_cmd or "", self.cfg.test_cmd or "",
                                  self.cfg.rescan_cmd or "")
            f.validation_status, f.validation_log = result.status, result.log
            if result.status != "failed":
                return
            error = result.log
