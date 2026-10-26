#!/usr/bin/env bash
# Run on the AIR-GAPPED server, inside the unpacked bundle directory.
# Loads the images and starts (or upgrades) the stack. Safe to re-run.
# Upgrades keep every record: the database is backed up first, and the Docker volumes are never removed
# (no 'down', no '-v'). Analyses interrupted by the restart resume where they stopped.
set -euo pipefail
cd "$(dirname "$0")"

command -v docker >/dev/null || { echo "Docker isn't installed on this server."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "The Docker Compose plugin (docker compose) isn't installed."; exit 1; }

echo "==> Checking the image archive"
sha256sum -c images.tar.gz.sha256

echo "==> Loading images (this takes a minute)"
docker load -i images.tar.gz

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo
  echo "Created .env from the example. Fill in VT_SECRET_KEY, POSTGRES_PASSWORD, VT_GITLAB_URL and the"
  echo "VT_LLM_* settings, add the certificates listed below, then run ./install.sh again."
  missing=1
else
  # Upgrades: point the existing .env at this bundle's version.
  version=$(grep '^VT_VERSION=' .env.example | cut -d= -f2)
  sed -i "s/^VT_VERSION=.*/VT_VERSION=${version}/" .env
  for key in VT_SECRET_KEY POSTGRES_PASSWORD; do
    grep -Eq "^${key}=.+" .env || { echo "Set ${key} in .env."; missing=1; }
  done
fi

# GitLab signed by a CA the image already trusts: no ca.pem needed, but the mount needs a file.
if [[ -f .env ]] && grep -Eq '^VT_CA_BUNDLE_IN_CONTAINER=.+' .env && [[ ! -f certs/ca.pem ]]; then
  : > certs/ca.pem
fi
# The server certificate is only needed when the nginx HTTPS profile is enabled.
https=""
[[ -f .env ]] && grep -Eq '^COMPOSE_PROFILES=.*https' .env && https=1
needed=(certs/ca.pem)
[[ -n "$https" ]] && needed+=(certs/server.crt certs/server.key)
for f in "${needed[@]}"; do
  [[ -f "$f" ]] || { echo "Missing $f"; missing=1; }
done
[[ -z "${missing:-}" ]] || {
  echo
  [[ -n "$https" ]] && echo "certs/server.crt + certs/server.key: HTTPS certificate for this server (from your internal CA)."
  echo "certs/ca.pem: the CA that signed GitLab's certificate (used for API calls and git clone)."
  exit 1
}
mkdir -p rules backups
version=$(grep '^VT_VERSION=' .env | cut -d= -f2)

# A full bundle contains every earlier patch. A patch-mode override left in this folder would mount old code over
# the new image, so it is set aside (not deleted).
if [[ -f docker-compose.override.yml ]]; then
  aside="docker-compose.override.yml.patch-mode-$(date +%Y%m%d-%H%M%S)"
  mv docker-compose.override.yml "$aside"
  echo "==> Set aside the patch-mode override as $aside; this bundle's image already has the patched code"
fi

# Upgrading a running stack (the compose project is always "vulntriage", whichever folder it was installed from).
active=""
db=$(docker compose ps -q db 2>/dev/null || true)
if [[ -n "$db" && "$(docker inspect -f '{{.State.Running}}' "$db" 2>/dev/null)" == "true" ]]; then
  active=$(docker compose exec -T db psql -U vt -d vulntriage -tAc     "select count(*) from jobs where status in ('running','queued')" 2>/dev/null || echo "?")
  backup="backups/vulntriage-before-${version}-$(date +%Y%m%d-%H%M%S).sql.gz"
  echo "==> Backing up the database to $backup"
  if ! docker compose exec -T db pg_dump -U vt vulntriage | gzip > "$backup"      || [[ $(gzip -dc "$backup" | head -c 100 | wc -c) -lt 100 ]]; then
    rm -f "$backup"
    echo "The database backup failed, so nothing was changed. Check: docker compose logs db"
    exit 1
  fi
  if [[ "$active" =~ ^[1-9] ]]; then
    echo "    $active analysis job(s) queued or running; they resume where they stopped after the upgrade."
  fi
fi

echo "==> Starting"
docker compose up -d
echo "==> Waiting for the web container to be healthy"
state=unknown
for _ in $(seq 1 45); do
  state=$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q web)" 2>/dev/null || echo unknown)
  [[ "$state" == "healthy" ]] && break
  sleep 4
done
docker compose ps
echo
if [[ "$state" != "healthy" ]]; then
  echo "The web container isn't healthy yet (state: $state). Check: docker compose logs web"
  [[ -n "${backup:-}" ]] && echo "Your data is untouched in the Docker volumes; a backup is in $backup."
  exit 1
fi
if [[ "$active" =~ ^[1-9] ]]; then
  echo "The $active interrupted analysis job(s) are back in the queue and continue from their finished findings."
  echo "Follow them with: docker compose logs -f worker"
fi
host=$(hostname -f 2>/dev/null || hostname)
if [[ -n "$https" ]]; then
  port=$(grep -E '^HTTPS_PORT=' .env | cut -d= -f2 || true); port=${port:-443}
  url="https://${host}:${port}/"
else
  port=$(grep -E '^HTTP_PORT=' .env | cut -d= -f2 || true); port=${port:-8080}
  url="http://${host}:${port}/"
fi
echo "Open ${url} and create the first account; it becomes the administrator."
