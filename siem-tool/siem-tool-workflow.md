# Cyber Chakshu SIEM-Tool Project Workflow

The `siem-tool` is a comprehensive Security Information and Event Management (SIEM) and digital forensics platform. It provides automated log parsing, attack detection, AI-assisted security analysis, and a full digital forensics pipeline.

## Project Structure

- **`frontend/`**: React-based dashboard (Vite + TypeScript) for visualizing logs, alerts, and forensic results.
- **`backend-python/`**: Core FastAPI backend handling log parsing, ML detection, SOC Analyst LLM integration, and forensic task management.
- **`backend/`**: Alternative TypeScript backend (Hono) optimized for Cloudflare Workers, handling log parsing and correlation.
- **`imageProcessor/`**: Core Python logic for the digital forensics pipeline, including extraction, preprocessing, and AI-based analysis.
- **`forensic-disk-analyzer/`**: Dockerized sub-project for specialized disk analysis. This provides a portable environment for running the forensic pipeline with all necessary system dependencies (e.g., `sleuthkit`, `libewf`).

---

## 1. Log Management & Analysis Workflow

### A. Log Ingestion
- Users upload logs via the frontend (text content, files, or multi-file for correlation).
- Support for 50+ log types (Apache, Nginx, SSH, Syslog, MySQL, Windows EVTX, etc.).
- **Auto-Detection**: The backend automatically identifies the log type using regex patterns and structure analysis.

### B. Parsing & Enrichment
- Logs are parsed into a standardized JSON format (`ParsedLogEntry`).
- **Keyword Detection**: Rule-based engine identifies known attack patterns (SQLi, Brute Force, XSS, etc.).
- **ML Detection**: Machine learning models classify entries and detect anomalies.
- **Enrichment**: Entries are tagged with severity, MITRE ATT&CK tactics/techniques, and risk scores.

### C. Multi-Log Correlation
- Correlates events across different log sources (e.g., matching a web attack to subsequent database activity).
- Identifies **Attack Chains** and calculates overall risk levels.

---

## 2. SOC Analyst AI Workflow

### A. Log Analysis
- Individual log entries can be sent to the **SOC Analyst AI** (powered by Llama 3.1 via OpenRouter).
- The AI provides a threat assessment, explains the attack, and gives remediation recommendations.
- **Fallback**: If the AI is unavailable, a rule-based system provides basic analysis.

### B. AI Chat & Assistance
- A chat interface allows security analysts to ask general questions or specific queries about detected threats.
- Context-aware responses based on the current log analysis.

### C. Feedback & Training
- Users can provide feedback (rating + text) on AI responses.
- Feedback is stored and can be used to generate training data for model refinement.

---

## 3. Digital Forensics Pipeline Workflow

The forensics workflow is managed by the `ForensicTaskManager` in the Python backend.

1.  **Start Task**: User provides a path to a disk image (`.e01`, `.dd`, `.raw`, `.img`).
2.  **Validation**: Pipeline checks the file integrity and format.
3.  **Extraction (`ForensicExtractor`)**: 
    - Identifies partitions.
    - Extracts system artifacts, user files, and configuration.
    - **Log Extraction (`LogExtractor`)**: Specifically targets and parses Windows Event Logs (`.evtx`).
4.  **Preprocessing (`ForensicPreprocessor`)**: Hashes files, extracts metadata, and prepares data for AI.
5.  **AI Analysis (`AIForensicAnalyzer`)**: 
    - Analyzes preprocessed data for Indicators of Compromise (IoCs).
    - Summarizes findings and assigns risk levels.
6.  **Anti-Forensic Detection (`AntiForensicAnalyzer`)**: Checks for attempts to hide or wipe data.
7.  **Reporting**:
    - Generates a structured JSON result.
    - Generates an interactive HTML report.
    - Generates a comprehensive PDF report (`ForensicPDFReport`).

---

## 4. Frontend Interaction

- **Dashboard**: Real-time visualization of log statistics, severities, and attack types.
- **Log Viewer**: Interactive table with smart filtering (by severity, attack type, IP, etc.).
- **Forensics UI**: Progress tracking for long-running forensic tasks and a detailed viewer for findings.
- **SOC Analyst Console**: Dedicated space for AI analysis and chat.

---

## Technical Stack

- **Frontend**: React, TypeScript, Vite, Tailwind CSS.
- **Backend (Python)**: FastAPI, Uvicorn, Scikit-learn (ML), OpenRouter (LLM).
- **Backend (TypeScript)**: Hono, Cloudflare Workers.
- **Forensics**: Python, `pytsk3`, `libewf`, `python-evtx`, `ReportLab` (PDF).
