# Multi-stage build for minimal image size
FROM python:3.11-slim AS builder

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final stage
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash cataloguser

WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/cataloguser/.local

# Copy application code
COPY --chown=cataloguser:cataloguser . .

# Create directories for mounted volumes
RUN mkdir -p /app/priv && \
    chown -R cataloguser:cataloguser /app

# Switch to non-root user
USER cataloguser

# Add local bin to PATH
ENV PATH=/home/cataloguser/.local/bin:$PATH

# Environment variables
ENV FLASK_APP=run.py
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

# Run application
CMD ["python", "run.py"]
