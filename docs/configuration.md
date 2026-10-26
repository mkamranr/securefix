# Configuration

All settings live in `.env` next to `docker-compose.yml`; see [`deploy/.env.example`](../deploy/.env.example) for
the full list. Some model settings can also be changed by administrators on the **Admin** page.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `VT_GITLAB_URL` | Base URL of the self-hosted GitLab |
| `VT_LLM_BASE_URL`, `VT_LLM_MODEL` | vLLM endpoint and served model name. These and the other `VT_LLM_*` values are defaults (see [Model settings](#model-settings-admin-page)) |
| `VT_LLM_API_KEY` | API key for vLLM, if it requires one |
| `VT_LLM_STRUCTURED_OUTPUT` | `true` to request `response_format: json_schema` from vLLM |
| `VT_SECRET_KEY` | Master secret for sessions and token encryption. Never change it after first use |
| `POSTGRES_PASSWORD` | Password of the bundled Postgres |
| `VT_CONTEXT_TOKEN_BUDGET` | Tokens of code per finding (default 100000; the model's window is larger, but precision drops on very long prompts) |
| `VT_TRIAGE_VOTES` | Independent triage runs per finding (default 3) |
| `VT_LLM_MAX_TOKENS` | Longest triage reply in tokens (default 4096, 1024 to 32768). A reply cut off at this limit is retried once with twice as many. The prompt plus the reply must fit the model's context length |
| `VT_LLM_THINKING` | Default for new analyses: `true` lets a reasoning model (Qwen3) think before it answers, `false` answers directly (default `true`). Users choose per analysis; it is sent to vLLM as `chat_template_kwargs.enable_thinking`. Thinking uses part of `VT_LLM_MAX_TOKENS` |
| `VT_LLM_PARALLEL` | Model requests one analysis sends at the same time (default 4, 1 to 32). Total load on vLLM is this × `VT_WORKER_THREADS` × worker containers; lower it if vLLM logs preemptions or requests hit the timeout |
| `VT_WORKER_THREADS` | Analysis jobs each worker container runs in parallel (default 2) |
| `VT_CA_BUNDLE_IN_CONTAINER` | CA bundle path inside the containers (default `/certs/ca.pem`, mounted from `certs/ca.pem`) |
| `VT_TOKENIZER_PATH` | Tokenizer directory for exact token counts (image built with `INSTALL_TOKENIZER=1`; mount the files) |
| `VT_CWE_XML` | MITRE CWE catalogue added to prompts, e.g. `/opt/rules/cwec_v4.15.xml` (optional) |
| `HTTP_PORT` | Host port the app is published on over plain HTTP (default 8080) |
| `VT_COOKIE_SECURE` | `false` for plain HTTP; `true` behind the HTTPS proxy |
| `COMPOSE_PROFILES=https`, `HTTPS_PORT` | Turn on the nginx HTTPS proxy and choose its host port (also set `VT_TRUSTED_PROXIES=*`) |

## Model settings (Admin page)

Administrators can override the vLLM URL, model, API key, timeout, *Parallel requests*, *Max tokens per reply*,
*Thinking* (the default for new analyses) and structured output under **Admin › Local model (vLLM)**. The overrides are stored in the database and apply to new analyses
without a restart. **Reset to the values in .env** undoes them.

## GitLab tokens

Each user saves their own token on the **Settings** page.

- `read_api` + `read_repository`: analyze commits.
- `api`: also create and comment on issues, open fix merge requests and dismiss findings.

A user needs at least the Developer role on a project to see its vulnerabilities. Creating an issue needs at least
the Reporter role, and linking it to a vulnerability needs Developer.

## Windows sign-in

Administrators set it up under **Admin › Windows sign-in (Active Directory)**:

| Field | Example | Notes |
| --- | --- | --- |
| Server URL | `ldaps://dc01.corp.example.com:636` | Or `ldap://…:389` with StartTLS. The certificate is checked against `certs/ca.pem` |
| Domain | `corp.example.com` | UPN suffix; used when there is no service account |
| Base DN | `DC=corp,DC=example,DC=com` | Where accounts are searched |
| Service account | `CN=svc-securefix,OU=Service Accounts,…` | Read-only account to look users up (recommended); password stored encrypted |
| User filter | `(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))` | Default |
| Allowed group | `CN=AppSec Triage,OU=Groups,…` | Optional; nested membership counts |
| Admin group | `CN=AppSec Admins,OU=Groups,…` | Optional; sets the role at every sign-in |

**Test saved settings** checks the connection, the service account and, optionally, one account and its groups. A
local account always wins over a Windows account with the same username.

## Fix validation

For each GitLab project, administrators can set up to three commands under **Admin › Fix validation commands**. They run in a
copy of the patched checkout, inside the worker container:

| Step | Example | Passes when |
| --- | --- | --- |
| Build | `mvn -q -DskipTests package` | exit code 0 |
| Tests | `pytest -q` | exit code 0 |
| Re-scan | `semgrep scan --metrics=off --config /opt/rules --error {files}` | exit code 0, i.e. the finding is gone |

`{files}` becomes the changed files. Without commands, fixes are shown as *not validated*.

The worker image contains Python, git and semgrep, but not your projects' toolchains (JDK, Maven, Node, .NET…). To
build and test those projects, extend the image on the build server before exporting:

```dockerfile
FROM vulntriage:1.0.0
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jdk-headless maven && rm -rf /var/lib/apt/lists/*
USER vt
```

Dependencies the builds download (Maven, npm, pip packages) must come from your internal mirrors. Set those up
through the toolchain's usual config files in the image.

These commands, and the projects' tests, run in the worker container, which has network access to GitLab and vLLM.
Keep that container on its own host or network segment.
