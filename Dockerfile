FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY traefikctl/ traefikctl/

# Runs as tillyadmin's UID/GID (set in docker-compose.yml) so generated
# files in the mounted dynamic dir match existing ownership.
EXPOSE 8080
CMD ["uvicorn", "traefikctl.web.app:app", "--host", "0.0.0.0", "--port", "8080"]
