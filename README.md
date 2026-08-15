# 🛡️ VANGUARD SecOps // URL Threat Analyzer (BACKEND)

**Vanguard SecOps (Core-V2)** is an enterprise-grade phishing detection engine and threat intelligence dashboard. It bridges the gap between machine learning and live network telemetry, providing real-time analysis of suspicious URLs through a modern Security Operations Center (SOC) terminal interface.

Engineered by Adriyan Biswas.

## ⚡ Core Features

*   **Machine Learning Heuristics:** Utilizes a highly optimized Random Forest classifier and TF-IDF vectorization to detect zero-day phishing patterns with high confidence.
*   **Live Network Intelligence:** Executes real-time DNS resolution, WHOIS queries, and SSL certificate handshakes to assess domain reputation and age without relying on external threat APIs.
*   **Algorithmic Threat Flags:** Identifies domain generation algorithms (DGA), high-entropy URLs, and deceptive brand impersonation.
*   **SOC Terminal UI:** A frictionless, dark-mode React frontend featuring glassmorphism, dynamic data matrices, and live local-storage scan history.

## 🏗️ System Architecture

The project is decoupled into a high-performance Python backend and a lightning-fast React frontend.

**Backend (Machine Learning API)**
*   **Framework:** FastAPI (Python)
*   **ML Engine:** Scikit-Learn, Joblib (Model Compression)
*   **Network Sockets:** Built-in Python `ssl`, `socket`, and `whois`
*   **Deployment:** Render
