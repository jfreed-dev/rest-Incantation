# Shared base: runtime dependencies + application code.
FROM python:3.11-slim AS base

WORKDIR /app

# Runtime dependencies only (no test toolchain).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code.
COPY . .

# Set Flask app and expose its port.
ENV FLASK_APP=app.py
EXPOSE 5000

# Production image — runtime dependencies only. Selected by the `app`
# compose service via `target: runtime`.
FROM base AS runtime
# Bind to 0.0.0.0 for container access.
CMD ["flask", "run", "--host=0.0.0.0"]

# Test image — adds the dev/test toolchain on top of the runtime base.
# Selected by the `test` compose service via `target: test`.
FROM base AS test
RUN pip install --no-cache-dir -r requirements-dev.txt
CMD ["pytest", "-v", "--cov=.", "--cov-report=term"]
