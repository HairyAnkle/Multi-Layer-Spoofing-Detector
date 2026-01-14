FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install Python dependencies
RUN pip install --upgrade pip

RUN pip install \
    --no-cache-dir \
    --default-timeout=300 \
    --retries=10 \
    numpy \
    pandas \
    scikit-learn==1.8.0 \
    xgboost==3.1.3 \
    joblib

# Copy backend + model
COPY integration/backend/ backend/
COPY integration/models/ models/

# Entrypoint
ENTRYPOINT ["python", "backend/spoofing_detector.py"]
