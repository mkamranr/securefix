import pytest

from app.patcher import EditError, apply_edits, unified_diff

SRC = "def f(x):\n    return run('%s' % x)\n\ndef g():\n    return 1\n"


def test_exact_edit():
    out = apply_edits({"a.py": SRC}, [{"file": "a.py", "original": "run('%s' % x)", "replacement": "run('?', x)"}])
    assert "run('?', x)" in out["a.py"]


def test_trailing_whitespace_tolerated():
    src = SRC.replace("def f(x):\n", "def f(x):   \r\n")
    edit = {"file": "a.py", "original": "def f(x):\n    return run('%s' % x)", "replacement": "def f(x):\n    return 0"}
    out = apply_edits({"a.py": src}, [edit])
    assert out["a.py"].startswith("def f(x):\n    return 0\n")


def test_ambiguous_and_missing_rejected():
    with pytest.raises(EditError, match="more than once"):
        apply_edits({"a.py": SRC}, [{"file": "a.py", "original": "return", "replacement": "x"}])
    with pytest.raises(EditError, match="wasn't found"):
        apply_edits({"a.py": SRC}, [{"file": "a.py", "original": "nope()", "replacement": "x"}])
    with pytest.raises(EditError, match="isn't in the analyzed files"):
        apply_edits({"a.py": SRC}, [{"file": "b.py", "original": "x", "replacement": "y"}])


def test_diff():
    changed = apply_edits({"a.py": SRC}, [{"file": "a.py", "original": "return 1", "replacement": "return 2"}])
    d = unified_diff({"a.py": SRC}, changed)
    assert "-    return 1" in d and "+    return 2" in d
