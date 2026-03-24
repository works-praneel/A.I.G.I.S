<div align="center">
  <img src="AIGIS%20Logo%201.jpg" alt="AIGIS Logo" width="350"/>
</div>

<h1 align="center">🛡️ A.I.G.I.S (Autonomous Intelligence & Guard Inspection System)</h1>

<div align="center">

![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)
![Llama3](https://img.shields.io/badge/AI-Llama_3-orange?logo=meta)
![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-blue?logo=postgresql)
![Python](https://img.shields.io/badge/Python-3.11-green?logo=python)

> **"Snyk + SonarQube + AI, running entirely on your laptop, for free."**

</div>

A.I.G.I.S is a containerized, strictly local, AI-powered security analysis pipeline. It bridges the gap between writing code and securing code by automating static analysis (SAST), malware detection, and web vulnerability scanning. It translates cryptic security tool outputs into plain-English, actionable remediation steps using a local LLM, compiling everything into a clean Executive PDF Report.

**Zero configuration. Zero privacy leaks. Zero cost.**

---

## ✨ Key Features

* **Universal Input:** Scan single files, full GitHub repositories, live URLs, multi-language `.zip` archives, and compiled binaries (`.exe`, `.elf`, `.bin`).
* **100% Local AI:** Leverages a locally hosted **Llama 3** model to generate custom, plain-English code fixes. Your proprietary source code never leaves your network.
* **Enterprise RBAC:** Built-in Role-Based Access Control featuring isolated user dashboards and a global Admin monitoring panel.
* **Unified PDF Reporting:** Aggregates findings from 15+ underlying security tools into a single, standardized report featuring CVSS v3.1 threat scoring.
* **Automated Sandbox Routing:** Automatically detects languages (Python, JS, Java, C/C++, Go, Ruby, PHP) and routes them to the correct isolated security engines.

---

## 🏗️ Architecture & Tech Stack

A.I.G.I.S is built on a resilient, fully Dockerized microservices architecture:
* **Frontend:** Streamlit (Python) with secure encrypted browser cookie session management.
* **Backend:** FastAPI (Python) for robust REST API routing.
* **Task Queue:** Celery + Redis for asynchronous background scanning and report generation.
* **Database:** PostgreSQL for reliable, persistent storage of user accounts, roles, and scan histories.
* **AI Engine:** Ollama running `llama3` for local inference.

---

## 🚀 Quickstart Guide

### Prerequisites
1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
2. Git installed.

### 1. Installation & Container Management

**Clone the repository:**
```bash
git clone [https://github.com/yourusername/A.I.G.I.S.git](https://github.com/yourusername/A.I.G.I.S.git)
cd A.I.G.I.S
```

**First-time build and start:**
```bash
docker compose up -d --build
```
*Note: On the very first run, a background sidecar container will automatically download the 4.7GB Llama 3 model directly to your local drive. Subsequent boots will take seconds.*

**Standard start (after initial build):**
```bash
docker compose up -d
```

**Stop and completely wipe containers/volumes:**
```bash
docker compose down -v
```

### 2. Access the Portal
Open your browser and navigate to `http://localhost:8501`. Register your first account (which automatically becomes the system Admin).

---

## 🗄️ Database Access

If you need to manually inspect the PostgreSQL database while the containers are running, you can drop directly into the database shell using the following commands:

**1. Enter the Database Shell:**
```bash
docker exec -it aigis-postgres psql -U aigis -d aigis
```

**2. View All Users:**
```sql
SELECT id, username, role_id, created_at FROM users;
```

**3. View All Reports:**
```sql
SELECT id, job_id, scan_type, target, vulnerability_count, threat_score FROM reports;
```

**4. View Scan History:**
```sql
SELECT id, input_name, input_type, status, created_at FROM scan_jobs;
```
*(Type `\q` and press Enter to exit the PostgreSQL shell).*

---

## 🛡️ Tools Under the Hood

A.I.G.I.S orchestrates an array of industry-standard security tools transparently inside its isolated worker container:

* **SAST (Code):** Semgrep, Bandit, ESLint, SpotBugs, Brakeman, Gosec, Flawfinder, PHPCS.
* **Secrets/Repos:** Gitleaks, Trufflehog.
* **Web/URL:** Nikto, Nmap, WhatWeb, Wafw00f.
* **Binary/Malware:** ClamAV, YARA, Checksec.py, Binwalk, Strings.

---
