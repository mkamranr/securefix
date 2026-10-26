# Development

## Set up and run

Python 3.12 (the version in the image) is required.

```bash
pip install -r requirements-dev.txt
VT_COOKIE_SECURE=false ./run.sh          # local run without HTTPS, settings from ./.env
```

## Tests

```bash
python -m pytest -q                      # SQLite
VT_DATABASE_URL=postgresql+psycopg://vt:pw@localhost/vulntriage python -m pytest -q   # Postgres
```

The tests run the whole flow (register, token, picker, analysis, validation, fix MR, posting, Excel report) against
fake GitLab and vLLM servers in `tests/fake_services.py`, so no network is needed. The validation tests use bash
commands, so run them on Linux or macOS (or in the container).

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
docs/                 documentation (copied into bundles and patches)
scripts/              build-and-export.sh (full bundle, needs Docker), build-patch.sh (code patch, no Docker)
Dockerfile
tests/
```

## Changing prompts

Bump `PROMPT_VERSION` in `app/prompts.py` whenever a prompt changes, so cached results from older prompts aren't
reused.

## Releasing

| Change | Build | Command |
| --- | --- | --- |
| New or compiled dependencies, image changes | Full bundle | `scripts/build-and-export.sh <version>` |
| App code, deploy files, pure-Python packages | Patch | `scripts/build-patch.sh <version>-p<n>` |

Both write to `dist/`, which is not committed. See [Deployment](deployment.md) for installing them.
