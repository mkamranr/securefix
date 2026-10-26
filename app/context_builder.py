"""Builds the code context for one finding, in priority layers, within a token budget.

Layers: 1) the finding's file  2) files on the scanner's taint trace  3) definitions of functions
called near the sink  4) callers of the enclosing function  5) security-relevant configuration.
Language-agnostic (regex + file search), so it works on any repository without extra tooling.
"""
import fnmatch
import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .llm_client import count_tokens

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "__pycache__",
             ".idea", ".gradle", "bin", "obj", ".next", "coverage"}
CODE_EXT = {".py", ".java", ".kt", ".scala", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php", ".cs", ".c",
            ".cc", ".cpp", ".h", ".hpp", ".rs", ".swift", ".m", ".groovy", ".vue", ".erb", ".jsp", ".html"}
CONFIG_PATTERNS = ["settings.py", "*security*.py", "middleware*.py", "urls.py", "*SecurityConfig*.java",
                   "*WebSecurity*.java", "*Filter*.java", "application*.yml", "application*.yaml",
                   "application*.properties", "web.xml", "*sanitiz*", "*validat*", "*escape*", "routes*.rb",
                   "*middleware*.js", "*middleware*.ts", "*csrf*", "*auth*config*"]
KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "new", "function", "def", "class", "print",
            "len", "str", "int", "range", "super", "this", "self", "typeof", "sizeof", "await", "async",
            "elif", "else", "try", "with", "assert", "lambda", "not", "and", "or", "in", "is", "import"}
INJECTION_RE = re.compile(
    r"(ignore (all|any|previous|the above)|disregard|as an ai|language model|llm|chatgpt|assistant|"
    r"note to (the )?(ai|reviewer|scanner)|mark (this|it) as (a )?false positive|not a vulnerability)",
    re.IGNORECASE)
MAX_FILE_BYTES = 400_000


@dataclass
class Chunk:
    path: str
    start: int
    end: int
    reason: str
    text: str
    tokens: int = 0


@dataclass
class Context:
    chunks: list[Chunk] = field(default_factory=list)
    tokens: int = 0
    truncated: bool = False
    injection_suspected: bool = False

    def render(self) -> str:
        return "\n\n".join(c.text for c in self.chunks)

    @property
    def files(self) -> list[dict]:
        return [{"path": c.path, "start": c.start, "end": c.end, "reason": c.reason, "tokens": c.tokens}
                for c in self.chunks]

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.render().encode()).hexdigest()


def read_lines(repo: Path, rel: str) -> list[str] | None:
    p = (repo / rel).resolve()
    if not str(p).startswith(str(repo.resolve())) or not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
        return None
    try:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def numbered(lines: list[str], start: int, end: int) -> str:
    width = len(str(end))
    return "\n".join(f"{i:>{width}} | {lines[i - 1]}" for i in range(start, end + 1))


def iter_code_files(repo: Path):
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if Path(name).suffix.lower() in CODE_EXT:
                yield Path(root, name)


def grep(repo: Path, pattern: str, max_hits: int = 40) -> list[tuple[str, int]]:
    """(relative path, line) hits for a Python regex. Uses ripgrep when installed."""
    hits: list[tuple[str, int]] = []
    if shutil.which("rg"):
        try:
            out = subprocess.run(["rg", "-n", "--no-heading", "-m", "5", "-e", pattern, "."], cwd=repo,
                                 capture_output=True, text=True, timeout=60).stdout
            for line in out.splitlines():
                path, lineno, _ = line.split(":", 2)
                if not any(part in SKIP_DIRS for part in Path(path).parts):
                    hits.append((path.removeprefix("./"), int(lineno)))
                if len(hits) >= max_hits:
                    break
            return hits
        except (subprocess.SubprocessError, ValueError):
            hits = []
    rx = re.compile(pattern)
    for p in iter_code_files(repo):
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            for n, text in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if rx.search(text):
                    hits.append((str(p.relative_to(repo)), n))
                    if len(hits) >= max_hits:
                        return hits
        except OSError:
            continue
    return hits


def definition_pattern(name: str) -> str:
    n = re.escape(name)
    return (rf"(def\s+{n}\s*\(|function\s+{n}\s*\(|func\s+(\([^)]*\)\s*)?{n}\s*\(|fn\s+{n}\s*[<(]|"
            rf"{n}\s*[:=]\s*(async\s*)?(function|\()|"
            rf"(public|private|protected|static|internal)[\w<>\[\], ]*\s{n}\s*\()")


ENCLOSING_RE = re.compile(r"(?:def|function|func|fn)\s+(\w+)\s*\(|"
                          r"(?:public|private|protected|static|internal)[\w<>\[\], ]*\s(\w+)\s*\(")


def called_names(lines: list[str], start: int, end: int) -> list[str]:
    seen, out = set(), []
    for line in lines[max(0, start - 16):min(len(lines), end + 5)]:
        for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(", line):
            if name not in KEYWORDS and name not in seen:
                seen.add(name)
                out.append(name)
    return out[:12]


def enclosing_function(lines: list[str], line: int) -> str | None:
    for i in range(min(line, len(lines)) - 1, max(-1, line - 400), -1):
        m = ENCLOSING_RE.search(lines[i])
        if m:
            return m.group(1) or m.group(2)
    return None


class ContextBuilder:
    def __init__(self, repo: Path, budget: int):
        self.repo = repo
        self.budget = budget
        self.ctx = Context()
        self._covered: dict[str, list[tuple[int, int]]] = {}

    def _covered_by(self, path, start, end) -> bool:
        return any(s <= start and end <= e for s, e in self._covered.get(path, []))

    def add(self, path: str, start: int | None, end: int | None, reason: str, radius: int = 40) -> bool:
        lines = read_lines(self.repo, path)
        if not lines:
            return False
        if start is None:
            s, e = 1, len(lines)
        else:
            s, e = max(1, start - radius), min(len(lines), (end or start) + radius)
        if self._covered_by(path, s, e):
            return True
        text = f"=== FILE: {path} (lines {s}-{e}) [{reason}] ===\n{numbered(lines, s, e)}"
        tokens = count_tokens(text)
        if self.ctx.tokens + tokens > self.budget:
            self.ctx.truncated = True
            return False
        self.ctx.chunks.append(Chunk(path, s, e, reason, text, tokens))
        self.ctx.tokens += tokens
        self._covered.setdefault(path, []).append((s, e))
        if INJECTION_RE.search("\n".join(lines[s - 1:e])):
            self.ctx.injection_suspected = True
        return True

    def build(self, finding) -> Context:
        path, start, end = finding.file, finding.start_line, finding.end_line or finding.start_line
        lines = read_lines(self.repo, path) or []

        # 1. The finding's file: whole file if it fits in half the budget, else a window plus its header.
        if lines:
            whole = count_tokens("\n".join(lines))
            if whole <= self.budget // 2 or not start:
                self.add(path, None, None, "file containing the finding")
            else:
                self.add(path, 1, 1, "file header / imports", radius=60)
                self.add(path, start, end, "finding location", radius=150)

        # 2. Taint trace from the scanner (Advanced SAST code flows).
        for step in (finding.code_flows or [])[:30]:
            self.add(step["file"], step["line"], step["line"], f"taint trace ({step.get('kind', 'step')})", radius=30)

        if not lines or not start:
            return self.ctx

        # 3. Definitions of functions called around the sink.
        for name in called_names(lines, start, end):
            for hit_path, hit_line in grep(self.repo, definition_pattern(name), max_hits=3):
                self.add(hit_path, hit_line, hit_line, f"definition of {name}()", radius=35)

        # 4. Callers of the enclosing function (where its input comes from).
        func = enclosing_function(lines, start)
        if func and func not in KEYWORDS:
            for hit_path, hit_line in grep(self.repo, rf"\b{re.escape(func)}\s*\(", max_hits=12):
                if hit_path == path and abs(hit_line - start) < 400:
                    continue
                self.add(hit_path, hit_line, hit_line, f"caller of {func}()", radius=20)

        # 5. Security-relevant configuration, smallest first.
        configs = []
        for p in self.repo.rglob("*"):
            if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(self.repo).parts):
                if any(fnmatch.fnmatch(p.name.lower(), pat.lower()) for pat in CONFIG_PATTERNS):
                    configs.append(p)
        for p in sorted(configs, key=lambda x: x.stat().st_size)[:10]:
            self.add(str(p.relative_to(self.repo)), None, None, "security-relevant configuration")
        return self.ctx
