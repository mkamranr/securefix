from pathlib import Path
from types import SimpleNamespace

from app.context_builder import ContextBuilder

REPO = Path(__file__).parent / "fixture_repo"


def finding(**kw):
    base = dict(file="app.py", start_line=7, end_line=7, code_flows=[])
    base.update(kw)
    return SimpleNamespace(**base)


def test_layers_and_injection_flag():
    ctx = ContextBuilder(REPO, budget=50_000).build(finding())
    reasons = [c.reason for c in ctx.chunks]
    assert reasons[0] == "file containing the finding"
    assert any("caller of get_user()" in r for r in reasons), reasons
    assert ctx.injection_suspected  # helpers.py talks to an "AI reviewer"
    assert "7 |     cur.execute" in ctx.render()


def test_budget_respected():
    ctx = ContextBuilder(REPO, budget=60).build(finding())
    assert ctx.tokens <= 60 and ctx.truncated
