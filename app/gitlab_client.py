"""GitLab REST + GraphQL client. Every call uses the signed-in user's own token, so GitLab
enforces that user's permissions for reads and write-backs."""
import base64
import io
import json
import logging
import os
import subprocess
import zipfile
from pathlib import Path
from urllib.parse import quote

import httpx

from .config import settings

log = logging.getLogger(__name__)

SAST_JOB_HINTS = ("sast",)  # job names like gitlab-advanced-sast, semgrep-sast


class GitLabError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class GitLabClient:
    def __init__(self, token: str, token_type: str = "access_token", base_url: str | None = None):
        self.base_url = (base_url or settings.gitlab_url).rstrip("/")
        self.token = token
        self.token_type = token_type
        headers = {"Authorization": f"Bearer {token}"} if token_type == "oauth" else {"PRIVATE-TOKEN": token}
        self.http = httpx.Client(base_url=f"{self.base_url}/api/v4", headers=headers,
                                 verify=settings.tls_verify, timeout=60)
        self.gql_http = httpx.Client(headers=headers, verify=settings.tls_verify, timeout=60)

    def close(self):
        self.http.close()
        self.gql_http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---------- low level ----------
    def _req(self, method: str, path: str, **kw) -> httpx.Response:
        try:
            r = self.http.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise GitLabError(f"Can't reach GitLab at {self.base_url}: {exc}") from exc
        if r.status_code == 401:
            raise GitLabError("GitLab rejected the token. Check it in Settings.", 401)
        if r.status_code == 403:
            raise GitLabError("Your GitLab token doesn't have permission for this action.", 403)
        if r.status_code >= 400:
            raise GitLabError(f"GitLab returned {r.status_code} for {path}: {r.text[:300]}", r.status_code)
        return r

    def get(self, path, **params):
        return self._req("GET", path, params=params).json()

    def post(self, path, payload):
        return self._req("POST", path, json=payload).json()

    def graphql(self, query: str, variables: dict | None = None) -> dict:
        try:
            r = self.gql_http.post(f"{self.base_url}/api/graphql", json={"query": query, "variables": variables or {}})
        except httpx.HTTPError as exc:
            raise GitLabError(f"Can't reach GitLab GraphQL: {exc}") from exc
        if r.status_code == 401:
            raise GitLabError("GitLab rejected the token. Check it in Settings.", 401)
        body = r.json()
        if body.get("errors"):
            raise GitLabError("GraphQL: " + "; ".join(e.get("message", "") for e in body["errors"]))
        return body.get("data") or {}

    # ---------- identity ----------
    def current_user(self) -> dict:
        return self.get("/user")

    def token_scopes(self) -> list[str]:
        """Scopes of a personal/project/group access token (not available for OAuth tokens)."""
        if self.token_type == "oauth":
            return []
        try:
            return self.get("/personal_access_tokens/self").get("scopes", [])
        except GitLabError:
            return []

    # ---------- picker ----------
    def projects(self, search: str = "", page: int = 1) -> list[dict]:
        return self.get("/projects", membership="true", simple="true", search=search, order_by="last_activity_at",
                        per_page=30, page=page)

    def project(self, project_id: int) -> dict:
        return self.get(f"/projects/{project_id}")

    @staticmethod
    def access_level(project: dict) -> int:
        """The user's role on a project from GET /projects/:id (30 = Developer); direct or through its group."""
        perms = project.get("permissions") or {}
        return max((perms.get(k) or {}).get("access_level") or 0 for k in ("project_access", "group_access"))

    def branches(self, project_id: int, search: str = "") -> list[dict]:
        return self.get(f"/projects/{project_id}/repository/branches", search=search, per_page=50)

    def commits(self, project_id: int, ref: str, page: int = 1) -> list[dict]:
        return self.get(f"/projects/{project_id}/repository/commits", ref_name=ref, per_page=20, page=page)

    def pipelines_for_sha(self, project_id: int, sha: str) -> list[dict]:
        return self.get(f"/projects/{project_id}/pipelines", sha=sha, order_by="id", sort="desc", per_page=10)

    def pipeline_jobs(self, project_id: int, pipeline_id: int) -> list[dict]:
        return self.get(f"/projects/{project_id}/pipelines/{pipeline_id}/jobs", per_page=100, include_retried="false")

    @staticmethod
    def is_sast_job(job: dict) -> bool:
        if any(a.get("file_type") == "sast" for a in job.get("artifacts") or []):
            return True
        return any(h in (job.get("name") or "").lower() for h in SAST_JOB_HINTS)

    def scan_status(self, project_id: int, sha: str) -> dict:
        """State of the SAST scan for a commit: none | running | failed | finished."""
        pipelines = self.pipelines_for_sha(project_id, sha)
        if not pipelines:
            return {"state": "none", "label": "No pipeline"}
        for p in pipelines:  # newest first
            sast = [j for j in self.pipeline_jobs(project_id, p["id"]) if self.is_sast_job(j)]
            if not sast:
                continue
            states = {j["status"] for j in sast}
            info = {"pipeline_id": p["id"], "pipeline_iid": p.get("iid"), "pipeline_url": p.get("web_url"),
                    "jobs": [{"id": j["id"], "name": j["name"], "status": j["status"]} for j in sast]}
            if states & {"created", "pending", "running", "waiting_for_resource", "preparing", "scheduled"}:
                return {**info, "state": "running", "label": "Scan running"}
            if "success" in states:
                return {**info, "state": "finished", "label": "Scanned"}
            return {**info, "state": "failed", "label": "Scan failed"}
        return {"state": "none", "label": "No SAST job"}

    def sast_finding_count(self, project_path: str, pipeline_iid: int) -> int | None:
        q = """query($p: ID!, $iid: ID!) { project(fullPath: $p) { pipeline(iid: $iid) {
                 securityReportSummary { sast { vulnerabilitiesCount } } } } }"""
        try:
            d = self.graphql(q, {"p": project_path, "iid": str(pipeline_iid)})
            return d["project"]["pipeline"]["securityReportSummary"]["sast"]["vulnerabilitiesCount"]
        except (GitLabError, KeyError, TypeError):
            return None

    # ---------- findings ----------
    def sast_report(self, project_id: int, job_id: int) -> dict:
        """gl-sast-report.json from a job's artifacts (raw path first, then the archive)."""
        try:
            r = self._req("GET", f"/projects/{project_id}/jobs/{job_id}/artifacts/gl-sast-report.json")
            return r.json()
        except GitLabError as exc:
            if exc.status not in (404, None):
                raise
        r = self._req("GET", f"/projects/{project_id}/jobs/{job_id}/artifacts")
        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            for name in zf.namelist():
                if name.endswith("gl-sast-report.json") or name.endswith("sast-report.json"):
                    return json.loads(zf.read(name))
        raise GitLabError(f"Job {job_id} has no SAST report artifact.")

    def sast_severity_counts(self, project_path: str, pipeline_iid: int) -> dict[str, int] | None:
        """Findings per severity for the commit picker (first 1000 findings; None if GitLab can't say)."""
        try:
            findings = self.pipeline_security_findings(project_path, pipeline_iid, max_pages=10)
        except GitLabError:
            return None
        counts: dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "unknown").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def pipeline_security_findings(self, project_path: str, pipeline_iid: int, max_pages: int = 1000) -> list[dict]:
        """Findings as GitLab tracks them for this pipeline: UUID, state, linked vulnerability ID."""
        q = """query($p: ID!, $iid: ID!, $after: String) { project(fullPath: $p) { pipeline(iid: $iid) {
          securityReportFindings(reportType: ["sast"], first: 100, after: $after) {
            pageInfo { hasNextPage endCursor }
            nodes { uuid title severity state
              vulnerability { id state }
              location { ... on VulnerabilityLocationSast { file startLine endLine } }
              identifiers { externalType name } } } } } }"""
        out, after = [], None
        for _ in range(max_pages):
            d = self.graphql(q, {"p": project_path, "iid": str(pipeline_iid), "after": after})
            conn = ((d.get("project") or {}).get("pipeline") or {}).get("securityReportFindings") or {}
            out.extend(conn.get("nodes") or [])
            if not (conn.get("pageInfo") or {}).get("hasNextPage"):
                return out
            after = conn["pageInfo"]["endCursor"]
        return out

    def file_raw(self, project_id: int, path: str, ref: str) -> str:
        r = self._req("GET", f"/projects/{project_id}/repository/files/{quote(path, safe='')}/raw", params={"ref": ref})
        return r.text

    # ---------- checkout ----------
    def checkout(self, http_url_to_repo: str, sha: str, branch: str, dest: Path) -> None:
        """Shallow fetch of exactly `sha`. The token is passed per command, never written to .git/config."""
        user = "oauth2"
        basic = base64.b64encode(f"{user}:{self.token}".encode()).decode()
        cfg = ["-c", f"http.extraHeader=Authorization: Basic {basic}"]
        if settings.tls_verify is False:
            cfg += ["-c", "http.sslVerify=false"]
        elif isinstance(settings.tls_verify, str):
            cfg += ["-c", f"http.sslCAInfo={settings.tls_verify}"]

        def git(*args, check=True):
            res = subprocess.run(["git", *cfg, *args], cwd=dest, capture_output=True, text=True, timeout=1800,
                                 env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
            if check and res.returncode != 0:
                raise GitLabError(f"git {args[0]} failed: {res.stderr.strip()[-500:]}")
            return res

        dest.mkdir(parents=True, exist_ok=True)
        git("init", "-q")
        git("remote", "add", "origin", http_url_to_repo)
        if git("fetch", "-q", "--depth", "1", "origin", sha, check=False).returncode != 0:
            # Server doesn't allow fetching by SHA: fetch the branch history instead.
            if git("fetch", "-q", "--depth", "200", "origin", branch, check=False).returncode != 0:
                git("fetch", "-q", "origin", branch)
        git("-c", "advice.detachedHead=false", "checkout", "-q", sha)

    # ---------- write-back ----------
    # ---------- issues for a finding ----------
    @staticmethod
    def issue_marker(finding_uuid: str) -> str:
        """Hidden line in the issues this app creates, so a finding's issue is found again without a vulnerability record."""
        return f"<!-- vulntriage-finding: {finding_uuid} -->"

    def _vulnerability_issues(self, vulnerability_gid: str) -> list[dict]:
        q = """query($id: VulnerabilityID!) { vulnerability(id: $id) { issueLinks { nodes {
                 issue { iid webUrl state projectId } } } } }"""
        d = self.graphql(q, {"id": vulnerability_gid})
        nodes = (((d.get("vulnerability") or {}).get("issueLinks") or {}).get("nodes")) or []
        return [{"project_id": n["issue"].get("projectId"), "iid": int(n["issue"]["iid"]),
                 "web_url": n["issue"]["webUrl"], "state": n["issue"].get("state")} for n in nodes if n.get("issue")]

    def find_finding_issue(self, project_id: int, finding_uuid: str, vulnerability_gid: str | None) -> dict | None:
        """An existing issue for the finding: one linked to its vulnerability, else one this app created for it.
        Open issues win over closed ones."""
        found = []
        if vulnerability_gid:
            try:
                found = self._vulnerability_issues(vulnerability_gid)
            except GitLabError as exc:
                log.warning("Couldn't read issue links of %s: %s", vulnerability_gid, exc)
        if not found:
            marker = self.issue_marker(finding_uuid)
            for i in self.get(f"/projects/{project_id}/issues", search=finding_uuid, **{"in": "description"},
                              per_page=20, order_by="created_at", sort="desc"):
                if marker in (i.get("description") or ""):
                    found.append({"project_id": i.get("project_id"), "iid": i["iid"], "web_url": i["web_url"],
                                  "state": i.get("state")})
        if not found:
            return None
        found.sort(key=lambda i: i.get("state") != "opened")
        issue = found[0]
        issue["project_id"] = issue.get("project_id") or project_id
        return issue

    def create_finding_issue(self, project_id: int, title: str, description: str,
                             vulnerability_gid: str | None) -> dict:
        """Confidential issue assigned to the token's owner, linked to the vulnerability when there is one."""
        me = self.current_user()
        issue = self.post(f"/projects/{project_id}/issues", {"title": title[:255], "description": description,
                                                             "assignee_ids": [me["id"]], "confidential": True})
        if vulnerability_gid:
            q = """mutation($issue: IssueID!, $vulns: [VulnerabilityID!]!) {
                     vulnerabilityIssueLinkCreate(input: {issueId: $issue, vulnerabilityIds: $vulns}) { errors } }"""
            try:
                d = self.graphql(q, {"issue": f"gid://gitlab/Issue/{issue['id']}", "vulns": [vulnerability_gid]})
                errors = (d.get("vulnerabilityIssueLinkCreate") or {}).get("errors")
                if errors:
                    log.warning("Issue %s not linked to %s: %s", issue["iid"], vulnerability_gid, errors)
            except GitLabError as exc:  # the issue is still found again through its marker
                log.warning("Issue %s not linked to %s: %s", issue["iid"], vulnerability_gid, exc)
        return {"project_id": project_id, "iid": issue["iid"], "web_url": issue["web_url"], "state": "opened"}

    def issue_note(self, project_id: int, issue_iid: int, body: str) -> dict:
        return self.post(f"/projects/{project_id}/issues/{issue_iid}/notes", {"body": body})

    def dismiss_vulnerability(self, vulnerability_gid: str, comment: str) -> dict:
        q = """mutation($id: VulnerabilityID!, $c: String) { vulnerabilityDismiss(input: {id: $id, comment: $c,
                 dismissalReason: FALSE_POSITIVE}) { vulnerability { id state } errors } }"""
        d = self.graphql(q, {"id": vulnerability_gid, "c": comment})["vulnerabilityDismiss"]
        if d.get("errors"):
            raise GitLabError("; ".join(d["errors"]))
        return d["vulnerability"] or {}

    def create_fix_mr(self, project_id: int, base_sha: str, target_branch: str, new_branch: str,
                      files: dict[str, str], title: str, description: str) -> dict:
        self.post(f"/projects/{project_id}/repository/branches", {"branch": new_branch, "ref": base_sha})
        self.post(f"/projects/{project_id}/repository/commits", {
            "branch": new_branch, "commit_message": title,
            "actions": [{"action": "update", "file_path": p, "content": c} for p, c in files.items()]})
        return self.post(f"/projects/{project_id}/merge_requests", {
            "source_branch": new_branch, "target_branch": target_branch, "title": title,
            "description": description, "remove_source_branch": True})
