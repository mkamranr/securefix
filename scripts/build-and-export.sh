#!/usr/bin/env bash
# Run on the INTERNET-CONNECTED build server. Produces one bundle to carry into the air gap:
#   dist/vulntriage-<version>.tar.gz  = images (app, Postgres, nginx) + compose files + install script
#
# Usage: scripts/build-and-export.sh [version]
#   PLATFORM=linux/amd64     target CPU architecture of the air-gapped server
#   INSTALL_SEMGREP=1        bake semgrep into the app image for the fix re-scan step (default 1)
#   INSTALL_TOKENIZER=0      bake transformers in for exact token counts (default 0)
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(date +%Y.%m.%d-%H%M)}"
PLATFORM="${PLATFORM:-linux/amd64}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.27-alpine}"
OUT="dist/vulntriage-${VERSION}"

echo "==> Building vulntriage:${VERSION} for ${PLATFORM}"
docker build --platform "$PLATFORM" \
  --build-arg INSTALL_SEMGREP="${INSTALL_SEMGREP:-1}" \
  --build-arg INSTALL_TOKENIZER="${INSTALL_TOKENIZER:-0}" \
  -t "vulntriage:${VERSION}" .

echo "==> Smoke test: the entrypoint is executable, the image imports and its tools are present"
docker run --rm --platform "$PLATFORM" "vulntriage:${VERSION}" \
  sh -c 'test -x run.sh && python3 -c "import app.main" && git --version && (command -v semgrep >/dev/null && semgrep --version || true)'

echo "==> Pulling ${POSTGRES_IMAGE} and ${NGINX_IMAGE}"
docker pull --platform "$PLATFORM" "$POSTGRES_IMAGE"
docker pull --platform "$PLATFORM" "$NGINX_IMAGE"

echo "==> Exporting images"
rm -rf "$OUT" && mkdir -p "$OUT/certs" "$OUT/rules" "$OUT/backups"
docker save "vulntriage:${VERSION}" "$POSTGRES_IMAGE" "$NGINX_IMAGE" | gzip > "$OUT/images.tar.gz"

cp deploy/docker-compose.yml deploy/nginx.conf deploy/install.sh "$OUT/"
sed "s/__VERSION__/${VERSION}/" deploy/.env.example > "$OUT/.env.example"
printf '\n# Images included in this bundle\nPOSTGRES_IMAGE=%s\nNGINX_IMAGE=%s\n' "$POSTGRES_IMAGE" "$NGINX_IMAGE" >> "$OUT/.env.example"
cp -r README.md docs "$OUT/"
chmod +x "$OUT/install.sh"
(cd "$OUT" && sha256sum images.tar.gz > images.tar.gz.sha256)

tar -C dist -czf "dist/vulntriage-${VERSION}.tar.gz" "vulntriage-${VERSION}"
(cd dist && sha256sum "vulntriage-${VERSION}.tar.gz" > "vulntriage-${VERSION}.tar.gz.sha256")
echo
echo "Bundle: dist/vulntriage-${VERSION}.tar.gz ($(du -h "dist/vulntriage-${VERSION}.tar.gz" | cut -f1))"
echo "Copy it and its .sha256 file to the air-gapped server, then run install.sh there (see README)."
