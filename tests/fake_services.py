"""Minimal fake GitLab and vLLM servers for offline end-to-end tests."""
import asyncio
import base64
import hashlib
import json
import secrets

from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse

TOKEN = "glpat-test-token-1234"
BOB_TOKEN = "glpat-bob-token-5678"
USERS = {TOKEN: {"id": 1, "username": "alice"}, BOB_TOKEN: {"id": 2, "username": "bob"}}
ACCESS = {TOKEN: 40, BOB_TOKEN: 30}  # role on project 1 per token (30 = Developer); tests may change it
# GitLab accounts that can "Sign in with GitLab" (they get OAuth tokens from /oauth/token).
ACCOUNTS = {"carol": {"id": 3, "username": "carol", "name": "Carol Jones", "email": "carol@corp.test", "state": "active"},
            "erin": {"id": 5, "username": "erin", "name": "Erin Wu", "email": "erin@corp.test", "state": "active"},
            "localdup": {"id": 6, "username": "localdup", "name": "Not the local account", "state": "active"},
            "frank": {"id": 7, "username": "frank", "name": "Frank", "state": "blocked"}}
OAUTH_APP = {"id": "app-id-123", "secret": "gloas-secret-456"}
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


def _token(request: Request) -> str | None:
    bearer = request.headers.get("authorization", "")
    return bearer.removeprefix("Bearer ") if bearer.startswith("Bearer ") else request.headers.get("private-token")


@gitlab.middleware("http")
async def auth(request: Request, call_next):
    if request.url.path.startswith("/oauth/"):
        return await call_next(request)
    if _token(request) not in USERS:
        return JSONResponse({"message": "401 Unauthorized"}, status_code=401)
    calls.append((request.method, request.url.path))
    return await call_next(request)


@gitlab.get("/api/v4/user")
def user(request: Request): return USERS[_token(request)]


@gitlab.get("/api/v4/personal_access_tokens/self")
def scopes(): return {"scopes": ["api"]}


PROJECT = {"id": 1, "path_with_namespace": "grp/app", "name_with_namespace": "grp / app", "default_branch": "main",
           "web_url": "http://gl/grp/app", "http_url_to_repo": "http://gl/grp/app.git"}


@gitlab.get("/api/v4/projects")
def projects(): return [PROJECT]


@gitlab.get("/api/v4/projects/1")
def project(request: Request):
    level = ACCESS[_token(request)]
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


# Group the security team is picked from. NO_ACCESS: members GitLab won't assign (no access to project 1).
GROUPS = [{"id": 50, "full_path": "sec/team", "full_name": "Security / Team"}]
GROUP_MEMBERS = [{"id": 11, "username": "sam", "name": "Sam Lee", "state": "active"},
                 {"id": 12, "username": "tia", "name": "Tia Ng", "state": "active"},
                 {"id": 13, "username": "uma", "name": "Uma Roy", "state": "active"},
                 {"id": 14, "username": "vic", "name": "Vic Old", "state": "blocked"}]
NO_ACCESS: set[int] = set()


@gitlab.get("/api/v4/groups")
def groups(search: str = ""): return [g for g in GROUPS if search in g["full_path"]]


@gitlab.get("/api/v4/groups/50/members/all")
def group_members(page: int = 1): return GROUP_MEMBERS if page == 1 else []


def _assignees(ids: list[int]) -> list[dict]:
    people = {u["id"]: u for u in [*USERS.values(), *GROUP_MEMBERS]}
    return [{"id": i, "username": people.get(i, {}).get("username", f"u{i}")} for i in ids if i not in NO_ACCESS]


def _set_assignees(issue: dict, ids: list[int]):
    issue["assignees"] = _assignees(ids)
    issue["assignee_ids"] = [a["id"] for a in issue["assignees"]]


@gitlab.post("/api/v4/projects/1/issues")
async def new_issue(request: Request):
    body = await request.json()
    store = gitlab.state.setdefault("issues", [])
    iid = len(store) + 1
    issue = {"id": 1000 + iid, "iid": iid, "project_id": 1, "state": "opened", "notes": [],
             "web_url": f"http://gl/grp/app/-/issues/{iid}", **body}
    _set_assignees(issue, body.get("assignee_ids") or [])
    store.append(issue)
    return issue


@gitlab.get("/api/v4/projects/1/issues/{iid}")
def get_issue(iid: int): return next(i for i in gitlab.state["issues"] if i["iid"] == iid)


@gitlab.put("/api/v4/projects/1/issues/{iid}")
async def edit_issue(iid: int, request: Request):
    issue = next(i for i in gitlab.state["issues"] if i["iid"] == iid)
    body = await request.json()
    gitlab.state.setdefault("issue_edits", []).append((iid, body))
    issue.update({k: v for k, v in body.items() if k != "assignee_ids"})
    if "assignee_ids" in body:
        _set_assignees(issue, body["assignee_ids"])
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
    body = await request.json()
    q = body["query"]
    if "vulnerabilityDismiss" in q:
        gitlab.state.setdefault("dismissed", []).append(body["variables"])
        return {"data": {"vulnerabilityDismiss": {"vulnerability": {"id": body["variables"]["id"], "state": "DISMISSED"},
                                                  "errors": []}}}
    links = gitlab.state.setdefault("vuln_links", [])  # (vulnerability gid, issue iid, link type)
    if "vulnerabilitiesCreateIssue" in q:
        if gitlab.state.get("old_gitlab"):
            return {"errors": [{"message": "Field 'vulnerabilitiesCreateIssue' doesn't exist on type 'Mutation'"}]}
        store = gitlab.state.setdefault("issues", [])
        iid = len(store) + 1
        vuln = body["variables"]["vulns"][0]
        store.append({"id": 1000 + iid, "iid": iid, "project_id": 1, "state": "opened", "notes": [],
                      "web_url": f"http://gl/grp/app/-/issues/{iid}", "title": "Investigate vulnerability",
                      "description": "Generated by GitLab", "confidential": False, "assignee_ids": [],
                      "assignees": []})
        links.append((vuln, iid, "created"))
        return {"data": {"vulnerabilitiesCreateIssue": {"issue": {"id": f"gid://gitlab/Issue/{1000 + iid}",
                                                                  "iid": str(iid), "webUrl": store[-1]["web_url"]},
                                                        "errors": []}}}
    if "vulnerabilityIssueLinkCreate" in q:
        iid = int(body["variables"]["issue"].rsplit("/", 1)[-1]) - 1000
        links.extend((v, iid, "related") for v in body["variables"]["vulns"])
        return {"data": {"vulnerabilityIssueLinkCreate": {"errors": []}}}
    if "issueLinks" in q:
        issues = {i["iid"]: i for i in gitlab.state.get("issues", [])}
        return {"data": {"vulnerability": {"issueLinks": {"nodes": [
            {"issue": {"iid": str(iid), "webUrl": issues[iid]["web_url"], "state": issues[iid]["state"],
                       "projectId": 1}}
            for v, iid, _ in links if v == body["variables"]["id"] and iid in issues]}}}}
    if "securityReportSummary" in q:
        return {"data": {"project": {"pipeline": {"securityReportSummary": {"sast": {"vulnerabilitiesCount": 2}}}}}}
    if "securityReportFindings" in q:
        return {"data": {"project": {"pipeline": {"securityReportFindings": {
            "pageInfo": {"hasNextPage": False, "endCursor": None},
            "nodes": [{"uuid": "uuid-1", "title": "SQL injection", "severity": "HIGH", "state": "DETECTED",
                       "vulnerability": None, "location": {"file": "app.py", "startLine": 7, "endLine": 7},
                       "identifiers": [{"externalType": "cwe", "name": "CWE-89"}]}]}}}}}
    return {"errors": [{"message": "unexpected query"}]}


# ---- OAuth provider. authorize() stands in for the user signing in on GitLab's page and approving.
oauth = {"codes": {}, "refresh": {}, "expires_in": 7200, "token_calls": []}


def authorize(params: dict, account: str) -> str:
    assert params["client_id"] == OAUTH_APP["id"] and params["response_type"] == "code"
    assert params["scope"] == "api read_repository" and params["code_challenge_method"] == "S256"
    code = secrets.token_urlsafe(8)
    oauth["codes"][code] = (account, params["code_challenge"], params["redirect_uri"])
    return code


def _issue(account: str) -> dict:
    access, refresh = "gloat-" + secrets.token_urlsafe(8), "glort-" + secrets.token_urlsafe(8)
    USERS[access] = ACCOUNTS[account]
    ACCESS[access] = 30
    oauth["refresh"][refresh] = (account, access)
    return {"access_token": access, "refresh_token": refresh, "token_type": "Bearer",
            "expires_in": oauth["expires_in"], "created_at": 0}


def revoke(access: str):
    USERS.pop(access, None)


@gitlab.post("/oauth/token")
def token(grant_type: str = Form(...), client_id: str = Form(""), client_secret: str = Form(""), code: str = Form(""),
          code_verifier: str = Form(""), redirect_uri: str = Form(""), refresh_token: str = Form("")):
    oauth["token_calls"].append(grant_type)
    if (client_id, client_secret) != (OAUTH_APP["id"], OAUTH_APP["secret"]):
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    if grant_type == "authorization_code":
        account, challenge, redirect = oauth["codes"].pop(code, (None, None, None))
        expected = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
        if account is None or expected != challenge or redirect != redirect_uri:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        return _issue(account)
    if grant_type == "refresh_token" and refresh_token in oauth["refresh"]:
        account, old_access = oauth["refresh"].pop(refresh_token)  # GitLab rotates both tokens
        revoke(old_access)
        return _issue(account)
    return JSONResponse({"error": "invalid_grant"}, status_code=400)


gitlab.state = {}

vllm = FastAPI()
vllm.state.load = {"now": 0, "peak": 0, "delay": 0.0}  # requests in flight, for the parallel-request tests
vllm.state.thinking = []  # chat_template_kwargs.enable_thinking of each request
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
    vllm.state.thinking.append((body.get("chat_template_kwargs") or {}).get("enable_thinking"))
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
        return {"choices": [{"message": {"content": json.dumps(out)[:40]}, "finish_reason": "length"}],
                "usage": {"completion_tokens": body["max_tokens"]}}
    content = json.dumps(out)
    if (body.get("chat_template_kwargs") or {}).get("enable_thinking"):  # as Qwen3 without a reasoning parser
        content = "<think>Let me trace the input from source to sink {first}.</think>\n\n" + content
    return {"choices": [{"message": {"content": content}, "finish_reason": "stop"}],
            "usage": {"completion_tokens": 400 if "<think>" in content else 120}}
