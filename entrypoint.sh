#!/bin/bash
set -e

# The qwen3:4b LLM runs in a *native* Ollama on the Windows host (GPU-accelerated).
# This container reaches it via OLLAMA_BASE_URL (host.docker.internal). We do a
# non-fatal reachability probe so startup logs make it obvious whether the host
# Ollama is up — the app also runs its own health check on initialization.
OLLAMA_URL="${OLLAMA_BASE_URL:-http://host.docker.internal:11434}"
echo "🔌 Backend will use EXTERNAL Ollama at: ${OLLAMA_URL}"

echo "⏳ Probing host Ollama (up to 15s)..."
reachable=0
for i in $(seq 1 15); do
    if curl -sf "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
        echo "✅ Host Ollama reachable (took ${i}s)"
        reachable=1
        break
    fi
    sleep 1
done

if [ "$reachable" -ne 1 ]; then
    echo "⚠️  Could not reach host Ollama at ${OLLAMA_URL}."
    echo "    Make sure native Ollama is running on the host with '${OLLAMA_MODEL:-qwen3:4b}' pulled."
    echo "    The API will still start; LLM-dependent features will fail until Ollama is reachable."
fi

echo "🌐 Starting Sentinel AI Backend..."
exec python -m uvicorn src.api:app --host 0.0.0.0 --port 8000
