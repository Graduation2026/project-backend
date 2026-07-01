# ─────────────────────────────────────────────────────────────────────────────
# Sentinel AI Backend — Python + Ghidra image (CPU-only).
# The qwen3:4b LLM runs in a *native* Ollama on the host (GPU-accelerated);
# this container reaches it over host.docker.internal, so Ollama is NOT
# installed here. PyTorch is installed CPU-only (no CUDA libs) since the
# container has no GPU passthrough.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.10-slim-bookworm

# Prevent Python from writing .pyc files and buffer stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# ── System dependencies (Java 17 for Ghidra) ────────────────────────────────
RUN apt-get update && apt-get install -y \
    build-essential \
    openjdk-17-jdk \
    wget \
    unzip \
    curl \
    zstd \
    && rm -rf /var/lib/apt/lists/*

# ── Ghidra 11.0.1 ───────────────────────────────────────────────────────────
RUN wget --progress=dot:giga https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20240130.zip \
    && unzip ghidra_11.0.1_PUBLIC_20240130.zip -d /opt \
    && rm ghidra_11.0.1_PUBLIC_20240130.zip \
    && mv /opt/ghidra_11.0.1_PUBLIC /opt/ghidra

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# ── Ollama model selection (LLM itself runs on the host, not here) ───────────
ENV OLLAMA_MODEL=qwen3:4b

# ── Python dependencies ─────────────────────────────────────────────────────
COPY requirements.txt .
# Install CPU-only PyTorch FIRST from the dedicated CPU index. This avoids
# pulling the ~4GB NVIDIA CUDA stack (useless here — no GPU in the container).
# Installing it up front satisfies the `torch>=2.0.0` pin in requirements.txt,
# so the subsequent install won't replace it with a CUDA build.
# --timeout/--retries keep large wheel downloads resilient on slow networks.
RUN pip install --no-cache-dir --timeout 1000 --retries 10 \
    --index-url https://download.pytorch.org/whl/cpu torch
RUN pip install --no-cache-dir --timeout 1000 --retries 10 -r requirements.txt

# ── Application source code ─────────────────────────────────────────────────
COPY src/ ./src/
COPY ghidra_scripts/ ./ghidra_scripts/
COPY artifacts/ ./artifacts/
COPY knowledge_base/ ./knowledge_base/

# ── Entrypoint script ───────────────────────────────────────────────────────
COPY entrypoint.sh /app/entrypoint.sh
# Strip CR from Windows CRLF line endings (otherwise the shebang becomes
# "/bin/bash\r" and the container fails with "no such file or directory").
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Expose FastAPI port
EXPOSE 8000

# Launch the FastAPI server (talks to the host's native Ollama)
ENTRYPOINT ["/app/entrypoint.sh"]
