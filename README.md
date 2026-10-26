# SecureFix: vulnerability triage

A web app for teams on an air-gapped network. A user picks a commit in self-hosted GitLab; the app pulls that commit's Advanced SAST report, has the locally hosted LLM (vLLM) decide for each finding whether it is real or a false positive, and proposes a validated code fix for real ones. Users then post the analysis to GitLab, open a fix merge request, or dismiss false positives, all with their own GitLab token.

Nothing in the app contacts the internet: no CDNs, web fonts, telemetry or model downloads. Images are built on an internet-connected server, exported as one bundle, and loaded and started on the air-gapped server.

## How it works

1. **Sign in.** With a Windows (Active Directory) account once an administrator sets up Windows sign-in, or with a local account an administrator created. The very first account, created on the first visit, becomes the administrator; there is no self-registration after that. Windows users get a profile on their first sign-in; their password stays in Active Directory, so they can't change or reset it in the app.
2. **Settings.** Each user saves a GitLab token (personal/project/group access token, or an OAuth token). It is checked against GitLab, then stored encrypted. Every GitLab call uses the acting user's token, so GitLab enforces their permissions.
3. **Analyze a commit.** Pick project, branch and commit on the Analyze Commit page. Each commit shows whether its SAST scan has finished, how many findings it has, and whether it was already analyzed. Only scanned commits can be analyzed. Choose which severities to analyze: Critical and High are checked by default, and findings of other severities are listed as skipped without using the model. The browser remembers the choice.
4. **Background job.** A worker
   - downloads `gl-sast-report.json` from the commit's SAST job, including Advanced SAST taint traces;
   - matches findings to GitLab's records (UUID, state, vulnerability ID) through GraphQL, and skips findings already dismissed or resolved;
   - shallow-checks out the exact commit (the token is passed per git command, never written to disk);
   - builds context per finding in layers within a token budget: the file, taint-trace files, definitions of called functions, callers of the enclosing function, security configuration;
   - runs triage several times (`VT_TRIAGE_VOTES`); any disagreement becomes **Needs review**;
   - for real findings, asks for search/replace edits, applies them, and runs the project's build, test and re-scan commands; on failure it retries once with the error output;
   - **copies earlier analyses**: a finding with the same vulnerability (scanner, rule, CWE), file and lines as one analyzed in an earlier analysis of the same project, and the same code on those lines, 10 lines around them and at each taint-trace step, gets that analysis copied instead of asking the model again. It is marked *Copied* with a link to the analysis it came from, and can be posted to GitLab like any other. Results are also reused when the whole context, model and prompt version are identical;
   - if a model reply is cut off at the token limit (*Max tokens per reply* on the Admin page), retries once with twice the limit and asks for a shorter answer; if one of the triage runs still returns an unreadable reply, the finding uses the other runs with lower confidence;
   - saves every finished finding and every model call as it goes, so a job interrupted by a restart or an upgrade resumes where it stopped instead of starting over.
5. **Results.** Per finding: verdict, confidence, reasoning, evidence, diff, validation output, and the code the model saw. Actions:
   - **Post analysis to GitLab issue**: comments on the finding's issue: one linked to its vulnerability record, or one this app created for it earlier. If there is none, it first creates a confidential issue (severity, location, scanner details), assigns it to the user who clicked, and links it to the vulnerability. Each analysis is posted once: afterwards the button is disabled and the page links to the comment. An analysis copied from an earlier scan counts as posted when that earlier analysis was posted, so the same comment isn't added twice. When the analysis is run again and the model produces a new result, that result can be posted to the same issue.
   - **Retry failed**: when findings of an analysis failed (e.g. the model was unreachable or its reply unreadable), *Retry N failed* analyzes only those again, in the same analysis. Finished findings and what was posted stay as they are.
   - **Post several at once**: tick the analyzed findings in the list (or the box in its header for all of them) and choose *Post N to GitLab issues*. The list's *GitLab issue* column shows which analyses are already posted; those can't be selected again.
   - **Open vulnerability in GitLab**: every finding links to its vulnerability page in GitLab (or, on a branch without a vulnerability record yet, the pipeline's security report), opening in a new tab.
   - **Open fix merge request**: new branch from the analyzed commit, one commit with the fix, MR into the analyzed branch.
   - **Dismiss as false positive**: only for findings with a vulnerability record (default branch). Never automatic.
   - **Download report (Excel)**: on the analysis page (and per row on the History page). The workbook has a *Summary* sheet (project, branch, commit, who ran it, totals per verdict and a severity × verdict table) and a *Findings* sheet with one row per finding: severity, verdict, confidence, finding, CWE, location (linked to the file at the analyzed commit), GitLab issue (linked), link to the vulnerability in GitLab, analysis posted (Yes/No), posted by and when, proposed fix and its validation, fix merge request, dismissed, copied from, scanner, status, reasoning and error. Columns are filterable and colour-coded; a running analysis downloads its current state.
   Every action is recorded on the finding with who did it.

## Requirements

- **Build server (internet access):** Docker with Buildx, about 3 GB free disk.
- **Air-gapped server:** Docker Engine 24+ with the Compose plugin (`docker compose`), about 5 GB free disk, and network access to GitLab and the vLLM server.
- GitLab Ultimate with Advanced SAST (other analyzers that produce `gl-sast-report.json` also work).
- vLLM with the OpenAI-compatible API. Structured outputs (`response_format: json_schema`) are used when `VT_LLM_STRUCTURED_OUTPUT=true`.

## Deploy with Docker

The stack is `web` (the app), `worker` (runs analyses) and `db` (Postgres), plus an optional `proxy` (nginx with HTTPS). By default `web` is served over plain HTTP on `HTTP_PORT` (8080) and nginx is off; Postgres publishes no port, so it never clashes with other databases on the host.

### 1. Build and export, on the internet-connected server

```bash
scripts/build-and-export.sh 1.0.0
# PLATFORM=linux/arm64 for ARM servers; INSTALL_SEMGREP=0 to leave semgrep out; INSTALL_TOKENIZER=1 to add transformers
```

This builds the app image, smoke-tests it, pulls Postgres and nginx, and writes one bundle:

```
dist/vulntriage-1.0.0.tar.gz          images + docker-compose.yml + nginx.conf + .env.example + install.sh
dist/vulntriage-1.0.0.tar.gz.sha256
```

Everything the app needs at runtime is inside the images, including `git` and, by default, `semgrep`.

### 2. Move the bundle into the air gap

Copy both files with your approved transfer process, then on the air-gapped server:

```bash
sha256sum -c vulntriage-1.0.0.tar.gz.sha256
tar xzf vulntriage-1.0.0.tar.gz && cd vulntriage-1.0.0
```

### 3. Configure and start, on the air-gapped server

```bash
./install.sh            # first run loads the images and creates .env, then stops
vi .env                 # VT_SECRET_KEY, POSTGRES_PASSWORD, VT_GITLAB_URL, VT_LLM_* (openssl rand -hex 32 for secrets)
cp /path/to/server.crt /path/to/server.key certs/   # only when the HTTPS proxy is enabled (see below)
cp /path/to/internal-ca.pem certs/ca.pem            # CA that signed GitLab's certificate
cp -r /path/to/semgrep-rules/* rules/               # optional, for the fix re-scan step
./install.sh            # starts the stack
```

Open `http://<server>:<HTTP_PORT>/` (default 8080) and create the first account; it becomes the administrator. Then, on the Admin page, set up Windows sign-in or add local accounts.

Plain HTTP sends passwords and GitLab tokens unencrypted, so use it only on a trusted network. To serve HTTPS through nginx instead, uncomment the "HTTPS via nginx" block in `.env`, add `certs/server.crt` and `certs/server.key`, remove the `ports:` entry of `web` in `docker-compose.yml`, and run `./install.sh`. No internal CA for the HTTPS certificate? Create a self-signed one on the server:
`openssl req -x509 -newkey rsa:3072 -nodes -days 825 -keyout certs/server.key -out certs/server.crt -subj "/CN=$(hostname -f)" -addext "subjectAltName=DNS:$(hostname -f)"`

### Upgrade

Build a new bundle with a new version, move it in, unpack it, copy your `.env`, `certs/` and `rules/` from the old directory, and run `./install.sh`. It loads the new images, points `.env` at the new version and recreates the containers. Data stays in the Docker volumes `vulntriage_db-data` and `vulntriage_app-data`.

When the stack is already running, `install.sh` first backs up the database to `backups/vulntriage-before-<version>-<date>.sql.gz` and stops without changing anything if the backup fails. It never removes the volumes. Analyses that are queued or running at that moment resume after the restart and continue from the findings they had already finished. A full bundle contains every earlier patch, so a `docker-compose.override.yml` left from patch mode is renamed to `docker-compose.override.yml.patch-mode-<date>` instead of mounting old code over the new image. To restore a backup: `gunzip -c backups/<file>.sql.gz | docker compose exec -T db psql -U vt -d vulntriage` (into an empty database).

1.2.0 adds `openpyxl` for the Excel report, so upgrade to it with the full bundle.

### Patch without new images

When app code or deploy files changed, and any new packages are pure Python (listed in `deploy/patch/vendor.txt`), skip the full bundle. Run `scripts/build-patch.sh <name>` on a machine with internet access and Python 3 (no Docker needed), move `dist/vulntriage-patch-<name>.tar.gz` and its `.sha256` into the air gap, and on the server run:

```bash
tar -xzf vulntriage-patch-<name>.tar.gz
bash vulntriage-patch-<name>/apply-patch.sh /path/to/installed/bundle
```

It backs up the current files into `patch-backup-<date>/`, copies the new code to `app/` and the new packages to `vendor/`, and restarts the stack, always including `web` and `worker` so they load the new code, then checks that the web container is healthy and can read the patched files. `docker-compose.override.yml` mounts both over the installed image. Data in the Postgres volume is untouched, and running analyses resume after the restart. The next full bundle replaces all of this. Packages with compiled code need a full bundle.

### Operate

```bash
docker compose ps                      # state and health
docker compose logs -f worker          # analysis progress and errors
docker compose up -d --scale worker=3  # more parallel analyses (also see VT_WORKER_THREADS)
docker compose exec db pg_dump -U vt vulntriage | gzip > backup-$(date +%F).sql.gz
```

Keep a copy of `.env`: without the same `VT_SECRET_KEY`, stored GitLab tokens can't be decrypted and users must enter them again.

## Configuration

All settings live in `.env`; see `.env.example` for the full list.

| Variable | Purpose |
| --- | --- |
| `VT_GITLAB_URL` | Base URL of the self-hosted GitLab |
| `VT_LLM_BASE_URL`, `VT_LLM_MODEL` | vLLM endpoint and served model name. These and the other `VT_LLM_*` values are defaults: administrators can override URL, model, API key, timeout, parallel requests and structured output on the Admin page (stored in the database, applied to new analyses without a restart, "Reset to the values in .env" undoes it) |
| `VT_SECRET_KEY` | Master secret for sessions and token encryption |
| `POSTGRES_PASSWORD` | Password of the bundled Postgres |
| `VT_CONTEXT_TOKEN_BUDGET` | Tokens of code per finding (default 100000; the model's window is larger, but precision drops on very long prompts) |
| `VT_TRIAGE_VOTES` | Independent triage runs per finding (default 3) |
| `VT_LLM_MAX_TOKENS` | Longest triage reply in tokens (default 4096, 1024 to 32768; also on the Admin page as *Max tokens per reply*). A reply cut off at this limit is retried once with twice as many. The prompt plus the reply must fit the model's context length |
| `VT_LLM_PARALLEL` | Model requests one analysis sends at the same time (default 4, 1 to 32; also on the Admin page as *Parallel requests*). The votes of a finding and several findings run at once, and vLLM processes them together, so a job finishes several times faster with the same results. 1 sends them one after another. Total load on vLLM is this times `VT_WORKER_THREADS` times worker containers; lower it if vLLM logs preemptions or requests hit the timeout |
| `VT_WORKER_THREADS` | Analysis jobs each worker container runs in parallel (default 2) |
| `VT_CA_BUNDLE_IN_CONTAINER` | CA bundle path inside the containers (default `/certs/ca.pem`, mounted from `certs/ca.pem`) |
| `VT_TOKENIZER_PATH` | Tokenizer directory for exact token counts (image built with `INSTALL_TOKENIZER=1`; mount the files) |
| `VT_CWE_XML` | MITRE CWE catalogue added to prompts, e.g. `/opt/rules/cwec_v4.15.xml` (optional) |
| `HTTP_PORT` | Host port the app is published on over plain HTTP (default 8080; pick any free one) |
| `VT_COOKIE_SECURE` | `false` for plain HTTP; `true` behind the HTTPS proxy |
| `COMPOSE_PROFILES=https`, `HTTPS_PORT` | Turn on the nginx HTTPS proxy and choose its host port (also set `VT_TRUSTED_PROXIES=*`) |

### GitLab token scopes

- `read_api` + `read_repository`: analyze commits.
- `api`: also create and comment on issues, open fix merge requests and dismiss findings.

Creating an issue needs at least the Reporter role; linking it to a vulnerability needs Developer.

The user needs at least the Developer role on a project to see its vulnerabilities.

### Windows sign-in (Admin page)

Administrators set it up under **Admin › Windows sign-in**:

| Field | Example | Notes |
| --- | --- | --- |
| Server URL | `ldaps://dc01.corp.example.com:636` | Or `ldap://…:389` with StartTLS. The certificate is checked against `certs/ca.pem` |
| Domain | `corp.example.com` | UPN suffix; used when there is no service account |
| Base DN | `DC=corp,DC=example,DC=com` | Where accounts are searched |
| Service account | `CN=svc-securefix,OU=Service Accounts,…` | Read-only account to look users up (recommended); password stored encrypted |
| User filter | `(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))` | Default |
| Allowed group | `CN=AppSec Triage,OU=Groups,…` | Optional; nested membership counts |
| Admin group | `CN=AppSec Admins,OU=Groups,…` | Optional; sets the role at every sign-in |

Users type `jdoe`, `CORP\jdoe` or `jdoe@corp.example.com`. **Test saved settings** checks the connection, the service account and, optionally, one account and its groups. A local account always wins over a Windows account with the same username.

### Fix validation (Admin page)

Per GitLab project, administrators set up to three commands that run in a copy of the patched checkout, inside the worker container:

| Step | Example | Passes when |
| --- | --- | --- |
| Build | `mvn -q -DskipTests package` | exit code 0 |
| Tests | `pytest -q` | exit code 0 |
| Re-scan | `semgrep scan --metrics=off --config /opt/rules --error {files}` | exit code 0, i.e. the finding is gone |

`{files}` becomes the changed files. Without commands, fixes are shown as "not validated".

The worker image contains Python, git and semgrep, but not your projects' toolchains (JDK, Maven, Node, .NET…). To build and test those projects, extend the image on the build server before exporting:

```dockerfile
FROM vulntriage:1.0.0
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jdk-headless maven && rm -rf /var/lib/apt/lists/*
USER vt
```

Dependencies the builds download (Maven, npm, pip packages) must come from your internal mirrors; set them up through the toolchain's usual config files in the image.

These commands, and the projects' tests, run in the worker container with network access to GitLab and vLLM. Keep that container on its own host or network segment.

## Security notes

- GitLab tokens are encrypted at rest (Fernet, key derived from `VT_SECRET_KEY` or `data/secret.key`) and never shown again after saving.
- Local passwords are hashed with scrypt; Windows passwords are only sent to the directory (an empty password is always rejected, so it can't become an anonymous bind). The vLLM API key and the LDAP service account password are encrypted at rest like GitLab tokens.
- Passwords are hashed with scrypt. Forms and API calls are CSRF-protected; cookies are `SameSite=Strict`.
- Analyzed code is untrusted input to the model. Prompts tell the model to treat it as data, and findings whose context contains text addressed to an AI or reviewer are flagged in the UI. Nothing is dismissed or merged automatically.
- Prompts and raw model responses are stored per finding (`llm_log`) for audit.

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest -q                      # SQLite
VT_DATABASE_URL=postgresql+psycopg://vt:pw@localhost/vulntriage python -m pytest -q   # Postgres
VT_COOKIE_SECURE=false ./run.sh          # local run without HTTPS, settings from ./.env
```

The tests run the whole flow (register, token, picker, analysis, validation, fix MR) against fake GitLab and vLLM servers in `tests/fake_services.py`; no network needed.

## Project layout

```
app/
  main.py             web routes: sign-in, settings, admin, picker API, jobs, write-back
  analyzer.py         one analysis job: report → findings → context → triage votes → fix → validation
  context_builder.py  layered code context within a token budget; prompt-injection flag
  gitlab_client.py    REST + GraphQL + git checkout, with the user's token
  llm_client.py       vLLM client with structured output and JSON recovery; admin overrides of its settings
  ldap_auth.py        Windows (Active Directory) sign-in over LDAP
  app_settings.py     settings administrators change in the app (database)
  patcher.py          search/replace edits, unified diff, validation commands
  report.py           Excel report of an analysis (openpyxl)
  prompts.py          system prompts, JSON schemas, GitLab note format
  worker.py           database-backed job queue and worker threads
  security.py         password hashing, token encryption
  db.py, config.py
  templates/, static/ server-rendered pages and plain JavaScript, no external assets
deploy/               docker-compose.yml, nginx.conf, .env.example, install.sh (copied into the bundle)
deploy/patch/         docker-compose.override.yml, apply-patch.sh, vendor.txt (copied into patches)
scripts/              build-and-export.sh (full bundle, needs Docker), build-patch.sh (code patch, no Docker)
Dockerfile
tests/
```
