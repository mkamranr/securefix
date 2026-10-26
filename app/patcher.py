"""Applies the model's search/replace edits and validates the result by build, tests and re-scan."""
import difflib
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import settings


class EditError(Exception):
    pass


def _locate(content: str, original: str) -> tuple[int, int]:
    """Exact match first; then a match that ignores trailing whitespace and CRLF differences."""
    count = content.count(original)
    if count == 1:
        i = content.index(original)
        return i, i + len(original)
    if count > 1:
        raise EditError("matches more than once; it needs more surrounding lines to be unique")

    norm = lambda s: "\n".join(l.rstrip() for l in s.replace("\r\n", "\n").split("\n"))  # noqa: E731
    target = norm(original).strip("\n")
    if not target:
        raise EditError("is empty")
    lines = content.split("\n")
    tlines = target.split("\n")
    matches = [i for i in range(len(lines) - len(tlines) + 1)
               if [l.rstrip("\r ").rstrip() for l in lines[i:i + len(tlines)]] == [t.rstrip() for t in tlines]]
    if len(matches) != 1:
        raise EditError("wasn't found in the file" if not matches else "matches more than once")
    start = sum(len(l) + 1 for l in lines[:matches[0]])
    end = start + sum(len(l) + 1 for l in lines[matches[0]:matches[0] + len(tlines)]) - 1
    return start, end


def apply_edits(originals: dict[str, str], edits: list[dict]) -> dict[str, str]:
    """Returns {path: new content}. Raises EditError naming the failing edit."""
    files = dict(originals)
    for n, e in enumerate(edits, 1):
        path = e.get("file", "")
        if path not in files:
            raise EditError(f"Edit {n} targets {path!r}, which isn't in the analyzed files.")
        try:
            s, t = _locate(files[path], e.get("original", ""))
        except EditError as exc:
            raise EditError(f"Edit {n} in {path}: the text to replace {exc}.") from exc
        files[path] = files[path][:s] + e.get("replacement", "") + files[path][t:]
    return {p: c for p, c in files.items() if c != originals[p]}


def unified_diff(originals: dict[str, str], changed: dict[str, str]) -> str:
    out = []
    for path, new in changed.items():
        out.extend(difflib.unified_diff(originals[path].splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))
    return "".join(out)


@dataclass
class ValidationResult:
    status: str  # passed | failed | not_configured
    log: str = ""
    steps: list[dict] = field(default_factory=list)


def validate(repo: Path, changed: dict[str, str], build_cmd: str, test_cmd: str, rescan_cmd: str) -> ValidationResult:
    """Copies the checkout, writes the patched files, runs the configured commands.

    rescan_cmd may contain {files} (space-separated changed paths). It must exit non-zero while the
    finding is still present, e.g.: semgrep scan --config /opt/rules --error {files}
    """
    steps = [(name, cmd) for name, cmd in (("build", build_cmd), ("test", test_cmd), ("rescan", rescan_cmd)) if cmd.strip()]
    if not steps:
        return ValidationResult("not_configured", "No build, test or re-scan command is set for this project.")
    with tempfile.TemporaryDirectory(dir=settings.data_dir) as tmp:
        work = Path(tmp) / "repo"
        shutil.copytree(repo, work, symlinks=True)
        for path, content in changed.items():
            (work / path).write_text(content, encoding="utf-8")
        files_arg = " ".join(shlex.quote(p) for p in changed)
        result = ValidationResult("passed")
        for name, cmd in steps:
            cmd = cmd.replace("{files}", files_arg)
            try:
                proc = subprocess.run(cmd, shell=True, cwd=work, capture_output=True, text=True,
                                      timeout=settings.validation_timeout_s)
                ok, output = proc.returncode == 0, (proc.stdout + proc.stderr)[-8000:]
            except subprocess.TimeoutExpired:
                ok, output = False, f"Timed out after {settings.validation_timeout_s}s."
            result.steps.append({"step": name, "command": cmd, "ok": ok})
            result.log += f"$ {cmd}\n{output}\n[{name}: {'ok' if ok else 'FAILED'}]\n\n"
            if not ok:
                result.status = "failed"
                break
        return result
