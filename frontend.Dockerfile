FROM python:3.11-slim

WORKDIR /app

COPY frontend_requirements.txt .
RUN pip install --no-cache-dir -r frontend_requirements.txt

COPY frontend/ ./frontend/

ENV PYTHONPATH="/app/frontend"

EXPOSE 8501

CMD ["streamlit", "run", "frontend/app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true"]