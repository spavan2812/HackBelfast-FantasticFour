FROM python:3.14-slim

WORKDIR /app

# Install curl (used by healthcheck scripts, keep image lean otherwise)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first — layer cached unless requirements change
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY . .

# Uploads directory must exist at runtime
RUN mkdir -p app/static/uploads

ENV PYTHONUNBUFFERED=1

EXPOSE 5000

# 2 workers, 300 s timeout (Ollama report generation can take ~2 min)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "300", "run:app"]
