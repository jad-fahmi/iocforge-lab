FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/iocforge

WORKDIR /app

RUN useradd --create-home --home-dir /home/iocforge --shell /usr/sbin/nologin iocforge

COPY pyproject.toml README.md ./
COPY ioc_enricher ./ioc_enricher
RUN pip install --no-cache-dir ".[api]"

USER iocforge
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["uvicorn", "ioc_enricher.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
