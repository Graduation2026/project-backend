# Sentinel AI - Binary Vulnerability Detection System

Sentinel AI is a professional, containerized microservice system that uses **Ghidra Reverse Engineering** and **Random Forest Machine Learning** to detect vulnerabilities in compiled binary files (.exe, .o, .elf, etc.).

This project is modularized into separate services, orchestrated with Docker for 100% portability.

## 🚀 Quick Start (Running the Project)

You only need **Docker Desktop** installed. 

### Step 1: Clone the Ecosystem
Because this is a microservice architecture, you must clone all 4 repositories into the same parent folder on your computer:
*   `project-backend`
*   `project-frontend`
*   `project-ml`
*   `project-reverse-engineering`

### Step 2: Launch the System
Navigate into the **`project-backend`** folder and run:
```bash
docker compose up --build -d
```
3.  **Access the Dashboard:** Open your browser and go to:
    [http://localhost:9090](http://localhost:9090)

---

## 🏗️ System Architecture

The system is built using a modern **Microservice Architecture**:

*   **Frontend (Port 9090):** An Nginx-powered web dashboard that handles file uploads and displays visual analysis results.
*   **Backend (Port 8000):** A FastAPI server that orchestrates the heavy lifting:
    *   **Reverse Engineering:** Uses an internal "Headless" Ghidra engine to disassemble binaries.
    *   **Machine Learning:** Uses a pre-trained Random Forest model (83% accuracy) to predict if the extracted opcodes represent a vulnerability.
    *   **API Docs:** Interactive documentation available at [http://localhost:8000/docs](http://localhost:8000/docs).

---

## 📁 Repository Structure

*   `project-frontend/`: The UI code, styles, and Nginx configuration.
*   `project-backend/`: The API logic, Ghidra runner, and AI model logic.
*   `artifacts/`: Contains the pre-trained ML models (`.pkl`) and model metadata.
*   `ghidra_scripts/`: The Java scripts used by Ghidra to extract features.

---

## 🛠️ For Developers

### Retraining the Model
If you wish to retrain the AI with new data, navigate to the `project-backend` folder and run the training script:
```bash
python scripts/train_model.py
```
*Note: This will automatically update `model_metadata.json` with new accuracy metrics.*

---

## 🎓 Graduation Project Details
- **Core Technologies:** Python, FastAPI, Docker, Ghidra, Scikit-learn, Nginx.
- **Vulnerability Logic:** Based on assembly opcode frequency analysis and threat-level lookup tables for critical mitigations.
