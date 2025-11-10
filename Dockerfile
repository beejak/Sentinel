# syntax=docker/dockerfile:1

FROM python:3.11-slim AS base
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT ["python", "main.py"]
# Usage examples:
# docker build -t mcp-scanner:latest .
# docker run --rm mcp-scanner:latest --help
