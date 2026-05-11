# Use Python 3.10 as base
FROM python:3.10-slim-bookworm

# Prevent Python from writing .pyc files and buffer stdout
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

# Install system dependencies (Java 17, wget, unzip)
RUN apt-get update && apt-get install -y \
    build-essential \
    openjdk-17-jdk \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra 11.0.1
RUN wget --progress=dot:giga https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20240130.zip \
    && unzip ghidra_11.0.1_PUBLIC_20240130.zip -d /opt \
    && rm ghidra_11.0.1_PUBLIC_20240130.zip \
    && mv /opt/ghidra_11.0.1_PUBLIC /opt/ghidra

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code, scripts, and baked artifacts
COPY src/ ./src/
COPY ghidra_scripts/ ./ghidra_scripts/
COPY artifacts/ ./artifacts/

# Expose FastAPI port
EXPOSE 8000

# Start the server
CMD ["python", "-m", "uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
