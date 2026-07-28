FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml README.md ./
COPY specter/ ./specter/

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["specter"]
CMD ["--help"]
