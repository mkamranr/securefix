# Deployment

SecureFix is built for air-gapped networks. Images are built on a server with internet access, exported as one
bundle, then loaded and started on the air-gapped server. Nothing in the app contacts the internet: no CDNs, web
fonts, telemetry or model downloads.

The stack is `web` (the app), `worker` (runs analyses) and `db` (Postgres), plus an optional `proxy` (nginx with
HTTPS). By default `web` is served over plain HTTP on `HTTP_PORT` (8080) and nginx is off. Postgres publishes no
port, so it never clashes with other databases on the host.

## Requirements

- **Build server (internet access):** Docker with Buildx, about 3 GB free disk.
- **Air-gapped server:** Docker Engine 24+ with the Compose plugin (`docker compose`), about 5 GB free disk, and
  network access to GitLab and the vLLM server.
- GitLab Ultimate with Advanced SAST (other analyzers that produce `gl-sast-report.json` also work).
- vLLM with the OpenAI-compatible API. Structured outputs (`response_format: json_schema`) are used when
  `VT_LLM_STRUCTURED_OUTPUT=true`.

## 1. Build and export (internet-connected server)

```bash
scripts/build-and-export.sh 1.0.0
# PLATFORM=linux/arm64 for ARM servers; INSTALL_SEMGREP=0 to leave semgrep out; INSTALL_TOKENIZER=1 to add transformers
```

This builds the app image, smoke-tests it, pulls Postgres and nginx, and writes one bundle:

```
dist/vulntriage-1.0.0.tar.gz          images + docker-compose.yml + nginx.conf + .env.example + install.sh + docs
dist/vulntriage-1.0.0.tar.gz.sha256
```

Everything the app needs at runtime is inside the images, including `git` and, by default, `semgrep`.

## 2. Move the bundle into the air gap

Copy both files with your approved transfer process, then on the air-gapped server:

```bash
sha256sum -c vulntriage-1.0.0.tar.gz.sha256
tar xzf vulntriage-1.0.0.tar.gz && cd vulntriage-1.0.0
```

## 3. Configure and start (air-gapped server)

```bash
./install.sh            # first run loads the images and creates .env, then stops
vi .env                 # VT_SECRET_KEY, POSTGRES_PASSWORD, VT_GITLAB_URL, VT_LLM_* (openssl rand -hex 32 for secrets)
cp /path/to/server.crt /path/to/server.key certs/   # only when the HTTPS proxy is enabled (see below)
cp /path/to/internal-ca.pem certs/ca.pem            # CA that signed GitLab's certificate
cp -r /path/to/semgrep-rules/* rules/               # optional, for the fix re-scan step
./install.sh            # starts the stack
```

Open `http://<server>:<HTTP_PORT>/` (default 8080) and create the first account; it becomes the administrator.
Then, on the **Admin** page, set up Windows sign-in or add local accounts. See [Configuration](configuration.md) for
every setting.

### HTTPS

Plain HTTP sends passwords and GitLab tokens unencrypted, so use it only on a trusted network. To serve HTTPS through
nginx instead:

1. uncomment the "HTTPS via nginx" block in `.env`;
2. add `certs/server.crt` and `certs/server.key`;
3. remove the `ports:` entry of `web` in `docker-compose.yml`;
4. run `./install.sh`.

No internal CA for the HTTPS certificate? Create a self-signed one on the server:

```bash
openssl req -x509 -newkey rsa:3072 -nodes -days 825 -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=$(hostname -f)" -addext "subjectAltName=DNS:$(hostname -f)"
```

## Upgrade with a full bundle

Build a new bundle with a new version and move it in. Unpack it, copy your `.env`, `certs/` and `rules/` from the old
directory, and run `./install.sh`. It loads the new images, points `.env` at the new version and recreates the
containers. Data stays in the Docker volumes `vulntriage_db-data` and `vulntriage_app-data`.

When the stack is already running, `install.sh` first backs up the database to
`backups/vulntriage-before-<version>-<date>.sql.gz`, and stops without changing anything if the backup fails. It never
removes the volumes. Analyses that are queued or running at that moment resume after the restart, continuing from
the findings they had already finished.

A full bundle contains every earlier patch. A `docker-compose.override.yml` left over from patch mode is therefore
renamed to `docker-compose.override.yml.patch-mode-<date>`, so it doesn't mount old code over the new image.

To restore a backup into an empty database:

```bash
gunzip -c backups/<file>.sql.gz | docker compose exec -T db psql -U vt -d vulntriage
```

1.2.0 adds `openpyxl` for the Excel report, so upgrade to it with the full bundle.

## Patch without new images

You can skip the full bundle when only app code or deploy files changed and any new packages are pure Python
(listed in `deploy/patch/vendor.txt`). On a machine with internet access and Python 3 (no Docker needed), run:

```bash
scripts/build-patch.sh <name>
```

Move `dist/vulntriage-patch-<name>.tar.gz` and its `.sha256` into the air gap, and on the server run:

```bash
sha256sum -c vulntriage-patch-<name>.tar.gz.sha256
tar -xzf vulntriage-patch-<name>.tar.gz
bash vulntriage-patch-<name>/apply-patch.sh /path/to/installed/bundle
```

The script backs up the current files into `patch-backup-<date>/`, copies the new code to `app/` and the new packages
to `vendor/`, and restarts the stack. It always restarts `web` and `worker` so they load the new code, then checks
that the web container is healthy and can read the patched files. `docker-compose.override.yml` mounts both
folders over the installed image.

The patch leaves the data in the Postgres volume untouched, and running analyses resume after the restart. The next
full bundle replaces all of this. Packages with compiled code need a full bundle.

## Operate

```bash
docker compose ps                      # state and health
docker compose logs -f worker          # analysis progress and errors
docker compose up -d --scale worker=3  # more parallel analyses (also see VT_WORKER_THREADS)
docker compose exec db pg_dump -U vt vulntriage | gzip > backup-$(date +%F).sql.gz
```

Keep a copy of `.env`. Without the same `VT_SECRET_KEY`, stored GitLab tokens can't be decrypted and users must
enter them again.
