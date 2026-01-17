# app/Dockerfile.app
FROM python:3.11-slim

WORKDIR /app
COPY app.py .

EXPOSE 5000 5001 5002

CMD ["python", "app.py"]