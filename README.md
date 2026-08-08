# Docker Image Security Scanner 🛡️🐳

A beginner-friendly, full-stack Python & Flask web application that inspects Docker container images for common security misconfigurations, calculates a quantitative security risk score, and generates educational reports with actionable remediation advice.

---

## 📌 Features

- **Docker SDK Integration**: Pulls and inspects low-level image metadata (`image.attrs` & `image.history()`) via `docker-py`.
- **4 Core Security Checks**:
  1. **Root User Execution Check**: Inspects `Config.User` to detect container processes running as UID 0 (root).
  2. **Exposed & Risky Ports Check**: Identifies high-risk administrative or database ports (SSH 22, Telnet 23, MongoDB 27017, Redis 6379, etc.).
  3. **Base Image & Tag Policy**: Warns against using mutable `:latest` or unpinned tags.
  4. **Hardcoded Secrets Detection**: Scans environment variables (`Config.Env`) and layer histories for keywords like `PASSWORD`, `API_KEY`, `TOKEN`, `AWS_ACCESS_KEY`, etc.
- **Quantitative Risk Scoring**: Computes a security score (0–100) with weighted penalties and assigns risk categories (**High Risk** `<50`, **Medium Risk** `50–75`, **Low Risk** `>75`).
- **Educational Remediation**: Provides plain-language recommendations with ready-to-use Dockerfile code fixes.
- **Graceful Error & Offline Support**: Handles invalid inputs, missing images, and includes a fallback offline demo mode if Docker Desktop is offline.

---

## 📁 Project Structure

```text
DOCKER IMAGE/
├── app.py                      # Flask web application entry point & routes
├── requirements.txt            # Python dependencies (Flask, docker, etc.)
├── README.md                   # Setup guide and educational documentation
├── scanner/
│   ├── __init__.py             # Package initializer
│   ├── docker_analyzer.py      # Docker SDK client & image metadata extraction
│   ├── security_checker.py     # Core security checking routines
│   ├── risk_assessment.py      # Security score & risk level calculation
│   └── report_generator.py    # Report synthesis & actionable recommendations
├── static/
│   └── style.css               # Modern, dark-mode CSS design system
└── templates/
    ├── index.html              # Scan input form & Docker daemon status badge
    └── report.html             # Security dashboard & recommendations view
```

---

## 🚀 Quickstart & Setup Guide

### Prerequisites
- **Python 3.10+** installed on your system.
- **Docker Desktop** installed and running locally.

### 1. Install Dependencies
Open a terminal in the project directory and install the required Python packages:

```bash
pip install -r requirements.txt
```

### 2. Verify Docker Desktop is Running
Make sure Docker Desktop is active. You can verify connection by running:

```bash
docker info
```

*(Note: If Docker Desktop is not running, the application will automatically offer simulated offline scan data so you can still preview and test all features).*

### 3. Run the Web Application

Launch the Flask development server:

```bash
python app.py
```

Or using the Flask CLI:

```bash
flask run --port=5000
```

### 4. Open in Browser
Navigate to `http://localhost:5000` in your web browser.

---

## 🧪 How to Test

1. **Test Standard Image**: Enter `nginx:latest` or `python:3.9-slim` and click **Scan**.
2. **Test Vulnerable Sample Image**: Click the quick-preset chip `vulnerable-app:latest` to observe how high-risk misconfigurations, root user execution, risky ports, and hardcoded secrets trigger score deductions and remediation advice.
3. **Test Input Validation**: Submit an invalid name like `invalid$$image` or empty input to observe graceful error handling.

---

## 📊 Security Risk Scoring Model

| Misconfiguration Issue | Penalty | Category |
| :--- | :--- | :--- |
| **Root User Execution** | `-25 pts` | Access Control |
| **Risky Exposed Port(s)** | `-15 pts` per port (max `-45 pts`) | Network Security |
| **Unpinned Tag (`:latest`)** | `-10 pts` | Supply Chain / Policy |
| **Hardcoded Secret Keyword** | `-15 pts` per secret (max `-45 pts`) | Credential Security |

- **Low Risk**: `76 – 100` (Green)
- **Medium Risk**: `50 – 75` (Yellow)
- **High Risk**: `< 50` (Red)

---

## 🎓 Educational Insights

This project demonstrates container security best practices:
- **Least Privilege**: Always run container workloads using an unprivileged `USER` directive.
- **Minimal Surface**: Never expose management protocols like SSH (port 22) or unauthenticated databases inside container images.
- **Immutability**: Pin base images to explicit version tags or digests for build reproducibility.
- **Secret Management**: Never hardcode credentials in Dockerfiles or `ENV` variables; inject secrets at runtime via secret managers or environment files.
