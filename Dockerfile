# Net Ward - multi-stage Docker image
#
# Build from project root:
#   docker build -t netward:latest .
#
# Run:
#   docker run -v ./config.json:/etc/netward/config.json netward:latest

# Stage 1: install dependencies into a clean venv
FROM python:3.12-slim AS builder

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt


# Stage 2: minimal runtime image
FROM python:3.12-slim AS runtime

# Non-root service account
RUN useradd --system --create-home --shell /bin/false netward

WORKDIR /app

# Bring in pre-built venv only (no build tools in production image)
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy the netward package; vendor patterns ship inside the image (data/ included)
COPY --chown=netward:netward netward/ ./netward/

# Operator mounts their config here at runtime; /app writable for default netward.db
RUN mkdir -p /etc/netward \
    && chown netward:netward /etc/netward \
    && chown netward:netward /app

# PYTHONPATH so `python -m netward` resolves the package from /app
ENV PYTHONPATH=/app

USER netward

ENTRYPOINT ["python", "-m", "netward"]
CMD ["--config", "/etc/netward/config.json"]
