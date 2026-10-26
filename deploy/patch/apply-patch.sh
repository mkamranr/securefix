#!/usr/bin/env bash
# Run on the AIR-GAPPED server. Applies a code patch to an installed bundle without loading new images:
# the patched app code is mounted over the code in the existing image (docker-compose.override.yml).
#
# Usage: bash apply-patch.sh /path/to/installed/bundle
set -euo pipefail
src="$(cd "$(dirname "$0")" && pwd)"
dest="${1:?Usage: bash apply-patch.sh /path/to/installed/bundle (the folder with docker-compose.yml and .env)}"
cd "$dest"
[[ -f docker-compose.yml && -f .env ]] || { echo "$dest has no docker-compose.yml or .env; point at the installed bundle."; exit 1; }

# The HTTP-only compose file publishes the app on HTTP_PORT: make sure nothing else listens there.
grep -q '^HTTP_PORT=' .env || printf '\nHTTP_PORT=8080\n' >> .env
grep -q '^VT_COOKIE_SECURE=' .env || printf 'VT_COOKIE_SECURE=false\n' >> .env
port=$(grep '^HTTP_PORT=' .env | cut -d= -f2)
ours=$(docker compose port web 8080 2>/dev/null || true)   # set when an earlier patch already published it
if [[ "$ours" != *":${port}" ]] && command -v ss >/dev/null && ss -ltn | grep -q ":${port} "; then
  echo "Port ${port} is already in use. Set HTTP_PORT in $dest/.env to a free port and run this again."
  exit 1
fi

backup="patch-backup-$(date +%Y%m%d-%H%M%S)"
echo "==> Backing up the current files to $dest/$backup"
mkdir "$backup"
for f in app vendor docs run.sh docker-compose.yml docker-compose.override.yml nginx.conf install.sh README.md requirements.txt; do
  if [[ -e "$f" ]]; then cp -a "$f" "$backup/"; fi
done

echo "==> Copying the patch"
rm -rf app vendor docs
cp -r "$src/app" app
cp -r "$src/vendor" vendor
cp -r "$src/docs" docs
cp "$src/run.sh" "$src/docker-compose.yml" "$src/docker-compose.override.yml" "$src/nginx.conf" \
   "$src/install.sh" "$src/README.md" "$src/requirements.txt" .
chmod 755 run.sh install.sh
chmod -R a+rX app vendor   # the containers run as uid 10001
docker compose config -q

# Running analyses survive this: the restart requeues them and they continue with the findings not yet finished.
running=$(docker compose exec -T db psql -U vt -d vulntriage -tAc \
  "select count(*) from jobs where status in ('running','queued')" 2>/dev/null || echo "?")
[[ "$running" == "0" || "$running" == "?" ]] || echo "    $running analysis job(s) queued or running; they resume after the restart."

echo "==> Restarting"
if ! grep -Eq '^COMPOSE_PROFILES=.*https' .env; then
  docker compose --profile https rm -sf proxy   # nginx is off unless the https profile is enabled
fi
docker compose up -d
# up -d leaves containers alone when the compose files didn't change (e.g. a second patch). They would keep the old
# code in memory and a mount of the replaced (now empty) app folder, so templates and static files go missing.
docker compose restart web worker
echo "==> Waiting for the web container to be healthy"
for _ in $(seq 1 30); do
  state=$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q web)" 2>/dev/null || echo unknown)
  [[ "$state" == "healthy" ]] && break
  sleep 4
done
docker compose ps
if [[ "$state" != "healthy" ]] || ! docker compose exec -T web test -r /opt/vulntriage/app/templates/home.html; then
  echo
  echo "The web container isn't healthy or can't read the patched app (state: $state). Check: docker compose logs web"
  echo "To undo: copy the files in $dest/$backup back, delete docker-compose.override.yml if the backup has none,"
  echo "and run: docker compose up -d && docker compose restart web worker"
  exit 1
fi
echo
echo "Patched. Open http://$(hostname -f 2>/dev/null || hostname):${port}/"
echo "To undo: copy the files in $dest/$backup back, delete docker-compose.override.yml if the backup has none,"
echo "and run: docker compose up -d && docker compose restart web worker"
