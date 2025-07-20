FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/results /app/logs

# Set environment variables
ENV PYTHONPATH=/app
ENV EVYL_CONFIG_PATH=/app/config

# Create non-root user for security
RUN useradd -m -u 1000 evyl && \
    chown -R evyl:evyl /app
USER evyl

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import evyl; print('OK')" || exit 1

# Default command
ENTRYPOINT ["python", "evyl.py"]
CMD ["--help"]

# Metadata
LABEL maintainer="Evyl Team <contact@evyl.dev>"
LABEL version="2.0.0"
LABEL description="Advanced Cloud Exploitation Framework"
LABEL org.opencontainers.image.title="Evyl Framework"
LABEL org.opencontainers.image.description="Advanced Cloud Exploitation Framework for Authorized Security Testing"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.authors="Evyl Team"
LABEL org.opencontainers.image.url="https://github.com/wKayaa/Evyl"
LABEL org.opencontainers.image.source="https://github.com/wKayaa/Evyl"
LABEL org.opencontainers.image.documentation="https://github.com/wKayaa/Evyl/wiki"
LABEL org.opencontainers.image.licenses="MIT"