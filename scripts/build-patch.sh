#!/usr/bin/env bash
# Run on a machine with internet access and Python 3 (no Docker needed). Packs the current app code and
# deploy files as a patch for a bundle that is already installed, so the server keeps its images:
#   dist/vulntriage-patch-<name>.tar.gz
# Packages added to requirements.txt since that bundle's image must be pure Python and listed in
# deploy/patch/vendor.txt; they are downloaded into the patch's vendor/ folder. Anything with compiled
# code needs a full bundle (build-and-export.sh).
#
# Usage: scripts/build-patch.sh [name]
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-$(date +%Y.%m.%d-%H%M)}"
OUT="dist/vulntriage-patch-${NAME}"
PY="${PYTHON:-$(command -v python3 || command -v python)}"

rm -rf "$OUT" && mkdir -p "$OUT/vendor"
cp -r app "$OUT/app"
find "$OUT/app" -name __pycache__ -type d -prune -exec rm -rf {} +

echo "==> Downloading pure-Python packages from deploy/patch/vendor.txt"
# Wheels only, built for any platform: what lands in vendor/ runs on the server's Linux image as-is.
"$PY" -m pip install --quiet --disable-pip-version-check --no-deps --only-binary=:all: \
  --platform any --python-version 3.12 --implementation py --target "$OUT/vendor" -r deploy/patch/vendor.txt
find "$OUT/vendor" \( -name __pycache__ -o -name bin \) -type d -prune -exec rm -rf {} +
if find "$OUT/vendor" -name '*.so' -o -name '*.pyd' | grep -q .; then
  echo "vendor/ contains compiled code, which won't run in the image. Build a full bundle instead."; exit 1
fi
cp -r docs "$OUT/docs"
cp run.sh README.md requirements.txt deploy/docker-compose.yml deploy/nginx.conf deploy/install.sh \
   deploy/patch/docker-compose.override.yml deploy/patch/apply-patch.sh "$OUT/"
chmod 755 "$OUT/run.sh" "$OUT/install.sh" "$OUT/apply-patch.sh"

tar -C dist -czf "dist/vulntriage-patch-${NAME}.tar.gz" "vulntriage-patch-${NAME}"
(cd dist && sha256sum "vulntriage-patch-${NAME}.tar.gz" > "vulntriage-patch-${NAME}.tar.gz.sha256")
echo
echo "Patch: dist/vulntriage-patch-${NAME}.tar.gz ($(du -h "dist/vulntriage-patch-${NAME}.tar.gz" | cut -f1))"
echo "On the server: tar -xzf vulntriage-patch-${NAME}.tar.gz && bash vulntriage-patch-${NAME}/apply-patch.sh /path/to/installed/bundle"
