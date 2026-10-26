# Security

SecureFix handles source code, GitLab credentials and write access to GitLab, so it is designed to keep all three
inside your network and under people's control.

## Data stays inside the network
- The model runs on your own vLLM server. Code and findings are never sent to an external service.
- Pages are rendered on the server with no CDNs, web fonts or telemetry; the app needs no internet access at runtime.

## Credentials
- **GitLab tokens** are encrypted at rest (Fernet, with a key derived from `VT_SECRET_KEY` or `data/secret.key`) and
  never shown again after saving. Every GitLab call uses the acting user's token, so GitLab enforces that user's
  permissions. During checkout the token is passed per git command and never written to disk.
- **Local passwords** are hashed with scrypt.
- **Windows passwords** are only sent to the directory. An empty password is always rejected, so a sign-in can't
  turn into an anonymous bind.
- The **vLLM API key** and the **LDAP service account password** are encrypted at rest like GitLab tokens.

## Web application
- Forms and API calls are CSRF-protected, and cookies are `SameSite=Strict`.
- `VT_COOKIE_SECURE=true` marks cookies secure behind the HTTPS proxy.
- Plain HTTP (the default) sends passwords and tokens unencrypted, so use it only on a trusted network. See
  [Deployment → HTTPS](deployment.md#https).

## Untrusted code and the model
- Analyzed code is untrusted input to the model. Prompts tell the model to treat it as data. Findings whose context
  contains text addressed to an AI or reviewer are flagged in the UI, so people treat those verdicts with suspicion.
- Triage runs several independent votes. Any disagreement becomes *Needs review* rather than a guess.
- Nothing is dismissed, merged or posted automatically. Every write to GitLab is a person's action, recorded with
  who did it and when.
- Prompts and raw model responses are stored per finding (`llm_log`) for audit.

## Validation commands
Build, test and re-scan commands run the analyzed project's own code inside the worker container. That container
has network access to GitLab and vLLM, so run it on its own host or network segment.

## Secrets to protect
| Secret | Where | If lost |
| --- | --- | --- |
| `VT_SECRET_KEY` | `.env` | Stored GitLab tokens can't be decrypted; users must enter them again |
| `POSTGRES_PASSWORD` | `.env` | Needed to reach the database |
| `data/secret.key` | app data volume | Fallback encryption key when `VT_SECRET_KEY` isn't set |
