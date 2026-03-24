# ─────────────────────────────────────────────────────────────
# NAIL Institute — AVE Public API
# Lightweight read-only FastAPI server for the AVE database
# ─────────────────────────────────────────────────────────────

FROM python:3.12-slim AS base

# Prevent .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# ── Dependencies ──────────────────────────────────────────────
COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# ── Application code ─────────────────────────────────────────
COPY api/ /app/api/
COPY ave-database/ /app/ave-database/

# ── Runtime config ───────────────────────────────────────────
ENV PUBLIC_API_HOST=0.0.0.0 \
    PUBLIC_API_PORT=8080 \
    PUBLIC_API_DB_PATH=/app/ave-database

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["python", "-m", "api"]
