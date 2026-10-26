# Build on a machine WITH internet access; export with scripts/build-and-export.sh.
# The resulting image needs nothing from the internet at runtime.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE}

# Optional extras, baked in at build time because they can't be downloaded later:
#   INSTALL_SEMGREP=1      semgrep CLI for the fix re-scan step (mount your rules at /opt/rules)
#   INSTALL_TOKENIZER=1    transformers, for exact token counts with the model's tokenizer
ARG INSTALL_SEMGREP=0
ARG INSTALL_TOKENIZER=0

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/vulntriage
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && if [ "$INSTALL_SEMGREP" = "1" ]; then pip install --no-cache-dir semgrep; fi \
 && if [ "$INSTALL_TOKENIZER" = "1" ]; then pip install --no-cache-dir "transformers>=4.40"; fi

COPY app/ app/
COPY run.sh .

# chmod: sources copied from Windows lose the execute bit, and CMD runs ./run.sh directly.
RUN chmod 755 run.sh \
 && useradd --system --create-home --uid 10001 vt \
 && mkdir -p /var/lib/vulntriage && chown vt:vt /var/lib/vulntriage
USER vt
ENV VT_DATA_DIR=/var/lib/vulntriage \
    PYTHONUNBUFFERED=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0
VOLUME ["/var/lib/vulntriage"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
CMD ["./run.sh"]
