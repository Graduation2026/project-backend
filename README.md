# Sentinel AI — Backend Audit Server & RAG Engine

This is the central orchestration server for the **Sentinel AI Ecosystem**. It handles dynamic C/C++ source compilation, disassembles binaries via headless Ghidra, runs GNN (GATv2) vulnerability prediction, generates LangChain Retrieval-Augmented Generation (RAG) remediations, compiles PDFs, and hosts the real-time interactive chatbot.

---

## ─── KEY INTEGRATED FEATURES ──────────────────────────────────────────────────

1.  **Dynamic Source Compiler:** On-the-fly MinGW wrapper that compiles raw `.c`/`.cpp` files into relocatable object code `.o` for instant analysis.
2.  **GNN Vulnerability Predictor:** Uses a Graph Attention Network (GATv2Conv + Global Readout) loaded with our optimal **Fold 4 (`best_fold4.pt`)** pre-trained weights to analyze basic-block control flow graph (CFG) structures in ~1.8 seconds.
3.  **LangChain RAG Security Auditor:** Queries a vectorized Chroma DB (memorized with memory safety guidelines, CWE-119, CWE-120, CWE-787, SEI CERT C) using `models/gemini-embedding-2` and `models/gemini-3-flash-preview` to write deep vulnerability compliance audits.
4.  **PDF Report Compiler:** Converts RAG markdown logs into downloadable, high-fidelity security audit PDFs.
5.  **Interactive Chatbot Sidebar:** Real-time conversational context loop via `POST /chat` linked directly to your RAG audit history.

---

## ─── DEVELOPER PREREQUISITES ────────────────────────────────────────────────

Your local machine needs the following environment setups to run the live disassembling and API server:

### 1. Java 17+ (Required by Ghidra)
Ghidra's headless analyzer is built on Java. Ensure you have Java 17 or higher in your environment path:
```bash
java -version
```

### 2. Ghidra Desktop Installation
1.  Download **Ghidra 12.0.3_PUBLIC** (or your preferred release) from the official [Ghidra Releases Page](https://github.com/NationalSecurityAgency/ghidra/releases).
2.  Extract the zip folder anywhere on your local computer (e.g., `C:\ghidra_12.0.3_PUBLIC` or `D:\ghidra_12.0.3_PUBLIC`).

---

## ─── QUICK SETUP & RUNNING ──────────────────────────────────────────────────

### Step 1: Create a local Virtual Environment & Install Libraries
Navigate into the `project-backend` folder:

```bash
# Windows
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Configure Environment Secrets (`.env`)
Create a file named `.env` in the root of `project-backend/` (this file is Git-ignored for privacy):

```env
# Google Gemini API Access
GOOGLE_API_KEY="AIzaSy..."
GEMINI_API_KEY="AIzaSy..."

# Path to your local Ghidra installation folder
GHIDRA_INSTALL_DIR="C:\ghidra_12.0.3_PUBLIC"
```

### Step 3: Run the FastAPI Application Server
Start the server using Uvicorn:

```bash
python -m uvicorn src.api:app --reload --host 127.0.0.1 --port 8000
```
*   The API endpoints will be active at `http://127.0.0.1:8000`.
*   Interactive documentation is available at `http://127.0.0.1:8000/docs`.

---

## ─── PROJECT ARCHITECTURE ────────────────────────────────────────────────────

*   `src/api.py`: FastAPI server routes, cors, upload handlers, compiler wrappers, and `/chat` endpoint.
*   `src/ghidra_runner.py`: Triggers headless Ghidra inside a subprocess to run `ExtractAllCFGs.java`.
*   `src/predictor.py`: Standardizes instructions, queries Word2Vec embeddings, and runs GNN PyTorch inference.
*   `src/rag_service.py`: Retrieval QA chain seeding, Chroma vector search, and Markdown generation.
*   `src/utils/pdf_generator.py`: Generates downloadable visual PDFs.
*   `artifacts/`: Contains our pre-trained model weights (`best_fold4.pt`, `asm2vec.model`).
*   `ghidra_scripts/ExtractAllCFGs.java`: Flat Java script executed headlessly by Ghidra to trace block instructions and connections.
