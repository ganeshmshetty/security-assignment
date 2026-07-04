# Orchestrated AI Security Reviewer

A dynamic multi-agent security scanner built on the `google-antigravity` SDK. The pipeline profiles target codebases, automatically determines the necessary specialized analysis agents (both predefined and dynamic), runs them in parallel, verifies potential issues, and generates a markdown report.

---

## 🚀 Setup Workflow

Follow these steps to set up the system on a new machine.

### 1. Install Prerequisites

Ensure you have the following package managers and tools installed:

- **Homebrew** (for macOS CLI tools):
  ```bash
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  ```
- **uv** (Modern, fast Python package and environment manager):
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
- **Node.js & npm** (For testing and running the Node.js sample target):
  ```bash
  brew install node
  ```

---

### 2. Install Security Scanners (Optional but Recommended)

The pipeline integrates with standard open-source CLI tools to perform scans. 

```bash
brew install semgrep trivy gitleaks
```

> [!NOTE]
> **Mock Fallbacks:** If these tools are not installed or available in your `PATH`, the codebase automatically falls back to simulated scanner results for the sample target so you can test the pipeline's agent flows immediately.

---

### 3. Clone and Setup Project

Clone the repository and sync the dependencies. `uv` will automatically download and manage the required Python version based on the project configuration.

```bash
git clone https://github.com/ganeshmshetty/security-assignment.git
cd security-assignment
uv sync
```

---

### 4. Google Cloud Platform (GCP) Authentication

The `google-antigravity` SDK uses Google Vertex AI (Gemini 3.5 Flash) under the hood. You must authenticate using Application Default Credentials (ADC).

1. Install the Google Cloud CLI (if not already installed):
   ```bash
   brew install --cask google-cloud-sdk
   ```
2. Authenticate your user account:
   ```bash
   gcloud auth login
   ```
3. Generate the application default credentials file:
   ```bash
   gcloud auth application-default login
   ```
4. Set the active project:
   ```bash
   gcloud config set project causal-hour-494002-e9
   ```
5. Set the quota project for billing:
   ```bash
   gcloud auth application-default set-quota-project causal-hour-494002-e9
   ```

---

## 🏃 Running the Security Reviewer

### Run the Pipeline
Run an automated security audit on any codebase target (e.g. the included `./sample_target`):

```bash
env PYTHONPATH=src uv run python -m security_assignment.main ./sample_target
```

### Manual Agent Overrides
If you want to bypass the dynamic Planner LLM and run specific predefined agents, use the `--agents` flag:

```bash
env PYTHONPATH=src uv run python -m security_assignment.main ./sample_target --agents sast,auth,dependency
```

---

## 🛠 Running the Sample Target

The `sample_target/` folder contains a intentionally vulnerable Node.js Express application (with SQL injection flaws and simulated hardcoded credentials) used to test the scanner.

1. Navigate to the folder and install dependencies:
   ```bash
   cd sample_target
   npm install
   ```
2. Start the application:
   ```bash
   npm start
   ```

---

## 📂 Project Structure & Architecture

```
├── README.md                      # Setup and usage guide
├── pyproject.toml                 # uv package definition
├── safety_policy.json             # Execution safety boundaries mapping
├── sample_target/                 # Vulnerable target codebase (Express + SQLite)
└── src/
    └── security_assignment/
        ├── main.py                # Pipeline orchestrator & Agent manager
        ├── agents/
        │   └── prompts.py         # System prompts for all agents & Planner
        └── tools/
            └── scanners.py        # CLI wrappers for Semgrep, Trivy, Gitleaks
```

### Review Phases
1. **Reconnaissance & Stack Profiling**: Profiles languages, database setups, and surfaces.
2. **Dynamic Planning**: A Planner LLM reviews the profile and maps the optimal analysis agents, dynamically creating specialized agents for novel surfaces (e.g., LDAP, WebSockets).
3. **Parallel Execution**: Dispatches Core (SAST, Dependency) and Specialized agents concurrently.
4. **Verification**: Validates findings to discard false positives.
5. **Reporting**: Compiles everything into `SECURITY_ASSIGNMENT_REPORT.md` inside the target directory.

