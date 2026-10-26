"""Minimal fake GitLab and vLLM servers for offline end-to-end tests."""
import asyncio
import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

TOKEN = "glpat-test-token-1234"
BOB_TOKEN = "glpat-bob-token-5678"
USERS = {TOKEN: {"id": 1, "username": "alice"}, BOB_TOKEN: {"id": 2, "username": "bob"}}
ACCESS = {TOKEN: 40, BOB_TOKEN: 30}  # role on project 1 per token (30 = Developer); tests may change it
SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
REPORT = {
    "version": "15.0.0",
    "scan": {"analyzer": {"name": "GitLab Advanced SAST"}},
    "vulnerabilities": [
        {"id": "rep-1", "name": "SQL injection", "severity": "High", "description": "User input in SQL.",
         "location": {"file": "app.py", "start_line": 7, "end_line": 7},
         "identifiers": [{"type": "cwe", "name": "CWE-89", "value": "89"},
                         {"type": "gitlab_advanced_sast_id", "name": "python-sqli", "value": "python-sqli"}],
         "details": {"code_flows": {"type": "code_flows", "items": [[
             {"type": "code_flow_node", "node_type": "source",
              "file_location": {"type": "file_location", "file_name": "app.py", "line_start": 12, "line_end": 12}},
             {"type": "code_flow_node", "node_type": "sink",
              "file_location": {"type": "file_location", "file_name": "app.py", "line_start": 7, "line_end": 7}}]]}}},
        {"id": "rep-2", "name": "Hard-coded value in query", "severity": "Low", "description": "Constant.",
         "location": {"file": "app.py", "start_line": 17, "end_line": 17},
         "identifiers": [{"type": "cwe", "name": "CWE-89", "value": "89"}]},
    ],
}

gitlab = FastAPI()
calls = []


@gitlab.middleware("http")
async def auth(request: Request, call_next):
    if request.headers.get("private-token") not in USERS:
        return JSONResponse({"message": "401 Unauthorized"}, status_code=401)
    calls.append((request.method, request.url.path))
    return await call_next(request)


@gitlab.get("/api/v4/user")
def user(request: Request): return USERS[request.headers["private-token"]]


@gitlab.get("/api/v4/personal_access_tokens/self")
def scopes(): return {"scopes": ["api"]}


PROJECT = {"id": 1, "path_with_namespace": "grp/app", "name_with_namespace": "grp / app", "default_branch": "main",
           "web_url": "http://gl/grp/app", "http_url_to_repo": "http://gl/grp/app.git"}


@gitlab.get("/api/v4/projects")
def projects(): return [PROJECT]


@gitlab.get("/api/v4/projects/1")
def project(request: Request):
    level = ACCESS[request.headers["private-token"]]
    return {**PROJECT, "permissions": {"project_access": {"access_level": level} if level else None, "group_access": None}}


@gitlab.get("/api/v4/projects/1/repository/branches")
def branches(): return [{"name": "feature/login", "default": False, "commit": {"id": SHA, "committed_date": "2026-10-20T10:00:00Z"}}]


@gitlab.get("/api/v4/projects/1/repository/commits")
def commits(): return [{"id": SHA, "short_id": SHA[:8], "title": "Add user lookup", "author_name": "Bob",
                        "committed_date": "2026-10-20T10:00:00Z"}]


@gitlab.get("/api/v4/projects/1/pipelines")
def pipelines(): return [{"id": 10, "iid": 5, "web_url": "http://gl/p/10"}]


@gitlab.get("/api/v4/projects/1/pipelines/10/jobs")
def jobs(): return [{"id": 100, "name": "gitlab-advanced-sast", "status": "success", "artifacts": [{"file_type": "sast"}]},
                    {"id": 101, "name": "unit-tests", "status": "success", "artifacts": []}]


@gitlab.get("/api/v4/projects/1/jobs/100/artifacts/gl-sast-report.json")
def report(): return REPORT


@gitlab.get("/api/v4/projects/1/repository/files/{path}/raw")
def raw(path: str):
    from fastapi.responses import PlainTextResponse
    from pathlib import Path
    return PlainTextResponse((Path(__file__).parent / "fixture_repo" / path).read_text())


@gitlab.get("/api/v4/projects/1/merge_requests")
def mrs(): return []


@gitlab.get("/api/v4/projects/1/issues")
def issues(search: str = ""):
    return [i for i in gitlab.state.setdefault("issues", []) if search in i["description"]]


@gitlab.post("/api/v4/projects/1/issues")
async def new_issue(request: Request):
    body = await request.json()
    store = gitlab.state.setdefault("issues", [])
    iid = len(store) + 1
    issue = {"id": 1000 + iid, "iid": iid, "project_id": 1, "state": "opened", "notes": [],
             "web_url": f"http://gl/grp/app/-/issues/{iid}", **body}
    store.append(issue)
    return issue


@gitlab.post("/api/v4/projects/1/issues/{iid}/notes")
async def issue_note(iid: int, request: Request):
    issue = next(i for i in gitlab.state["issues"] if i["iid"] == iid)
    issue["notes"].append((await request.json())["body"])
    return {"id": 500 + len(issue["notes"]), "body": issue["notes"][-1]}


@gitlab.post("/api/v4/projects/1/repository/branches")
async def new_branch(request: Request): return {"name": (await request.json())["branch"]}


@gitlab.post("/api/v4/projects/1/repository/commits")
async def new_commit(request: Request):
    body = await request.json()
    gitlab.state["last_commit"] = body
    return {"id": "f" * 40}


@gitlab.post("/api/v4/projects/1/merge_requests")
async def new_mr(request: Request): return {"iid": 7, "web_url": "http://gl/grp/app/-/merge_requests/7"}


@gitlab.post("/api/graphql")
async def graphql(request: Request):
    q = (await request.json())["query"]
    if "securityReportSummary" in q:
        return {"data": {"project": {"pipeline": {"securityReportSummary": {"sast": {"vulnerabilitiesCount": 2}}}}}}
    if "securityReportFindings" in q:
        return {"data": {"project": {"pipeline": {"securityReportFindings": {
            "pageInfo": {"hasNextPage": False, "endCursor": None},
            "nodes": [{"uuid": "uuid-1", "title": "SQL injection", "severity": "HIGH", "state": "DETECTED",
                       "vulnerability": None, "location": {"file": "app.py", "startLine": 7, "endLine": 7},
                       "identifiers": [{"externalType": "cwe", "name": "CWE-89"}]}]}}}}}
    return {"errors": [{"message": "unexpected query"}]}


gitlab.state = {}

vllm = FastAPI()
vllm.state.load = {"now": 0, "peak": 0, "delay": 0.0}  # requests in flight, for the parallel-request tests
vllm.state.cut = {"left": 0, "seen": []}  # replies to cut off at the token limit, and each request's (max_tokens, user)


@vllm.get("/v1/models")
def models(): return {"data": [{"id": "test-model"}]}


@vllm.post("/v1/chat/completions")
async def chat(request: Request):
    load = vllm.state.load
    load["now"] += 1
    load["peak"] = max(load["peak"], load["now"])
    try:
        await asyncio.sleep(load["delay"])
        return await _chat(request)
    finally:
        load["now"] -= 1


async def _chat(request: Request):
    body = await request.json()
    system, user = body["messages"][0]["content"], body["messages"][1]["content"]
    cut = vllm.state.cut
    cut["seen"].append((body["max_tokens"], user))
    assert body["response_format"]["type"] == "json_schema"
    if "triaging" in system:
        if "Location: app.py:7-7" in user:
            out = {"verdict": "true_positive", "confidence": 0.9, "source": "request.args name (app.py:12)",
                   "sink": "cur.execute (app.py:7)", "mitigations": "none",
                   "reasoning": "The name parameter is formatted into SQL.", "evidence": ["app.py:7 - string formatting into SQL"]}
        else:
            out = {"verdict": "false_positive", "confidence": 0.8, "source": "constant", "sink": "cur.execute",
                   "mitigations": "constant query", "reasoning": "The query is a constant.", "evidence": ["app.py:17"]}
    else:
        out = {"edits": [{"file": "app.py",
                          "original": "    cur.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)",
                          "replacement": "    cur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))"}],
               "explanation": "Use a parameterized query.", "suggested_test": "def test_quote(): get_user(\"x'\")"}
    if cut["left"] > 0:
        cut["left"] -= 1
        return {"choices": [{"message": {"content": json.dumps(out)[:40]}, "finish_reason": "length"}]}
    return {"choices": [{"message": {"content": json.dumps(out)}, "finish_reason": "stop"}]}
