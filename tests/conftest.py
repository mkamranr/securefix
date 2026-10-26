import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
import uvicorn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


GL_PORT, LLM_PORT = _free_port(), _free_port()
os.environ.update({
    "VT_DATA_DIR": tempfile.mkdtemp(prefix="vt-test-"),
    "VT_GITLAB_URL": f"http://127.0.0.1:{GL_PORT}",
    "VT_LLM_BASE_URL": f"http://127.0.0.1:{LLM_PORT}/v1",
    "VT_LLM_MODEL": "test-model",
    "VT_EMBEDDED_WORKER": "false",
    "VT_COOKIE_SECURE": "false",
    "VT_TRIAGE_VOTES": "3",
})


def _serve(app, port):
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("fake server didn't start")


@pytest.fixture(scope="session", autouse=True)
def fake_services():
    import fake_services as fs
    _serve(fs.gitlab, GL_PORT)
    _serve(fs.vllm, LLM_PORT)
    return fs
