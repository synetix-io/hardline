FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY hardline ./hardline
RUN pip install .

# Non-root; the scan counter is the only thing ever written.
RUN useradd -r -u 1001 hardline && mkdir -p /app/data && chown hardline /app/data
USER hardline
ENV HARDLINE_COUNTER=/app/data/scans.json

EXPOSE 8080
CMD ["uvicorn", "hardline.app:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips=*"]
