# Orchestrated AI Security Reviewer

A dynamic multi-agent security scanner built on the `google-antigravity` SDK. The pipeline profiles target codebases, automatically determines the necessary specialized analysis agents (both predefined and dynamic), runs them in parallel, verifies potential issues, and generates a markdown report.

---

## 🚀 Setup Workflow (Windows)

Follow these steps to set up the system on a new Windows computer.

### 1. Install Prerequisites

Open **PowerShell** (as Administrator) and run the following command to install the required tools using `winget` (Windows Package Manager, built into Windows 10 & 11) and PowerShell scripts:

- **Git** (Version control):
  ```powershell
  winget install --id Git.Git -e --source winget
  ```
- **Node.js & npm** (For testing and running the Node.js sample target):
  ```powershell
  winget install --id OpenJS.NodeJS -e --source winget
  ```
- **uv** (Modern, fast Python package and runtime manager):
  ```powershell
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  ```
  *(After installing, restart your PowerShell window to ensure the `uv` command is available in your PATH).*

---

### 2. Install Security Scanners (Optional but Recommended)

The pipeline integrates with open-source security binaries to perform scans. You can install them on Windows as follows:

- **Gitleaks** (Secrets detection):
  ```powershell
  winget install --id Gitleaks.Gitleaks -e --source winget
  ```
- **Trivy** (Dependency audit):
  ```powershell
  winget install --id aquasecurity.trivy -e --source winget
  ```
- **Semgrep** (Static analysis):
  Semgrep can be installed via Python's package manager:
  ```powershell
  pip install semgrep
  ```

> [!NOTE]
> **Mock Fallbacks:** If these tools are not installed or available in your environment, the pipeline automatically falls back to simulated scanner results for the sample target so you can test the pipeline's agent flows immediately.

---

### 3. Clone and Setup Project

Clone the repository and sync the dependencies. `uv` will automatically download and manage the correct Python runtime on Windows:

```powershell
git clone https://github.com/ganeshmshetty/security-assignment.git
cd security-assignment
uv sync
```

---

### 4. Google Cloud Platform (GCP) Authentication

The `google-antigravity` SDK uses Google Vertex AI (Gemini 3.5 Flash) under the hood. You must authenticate using Application Default Credentials (ADC).

1. Install the Google Cloud CLI for Windows:
   ```powershell
   winget install --id Google.CloudSDK -e --source winget
   ```
   *(Or download the standalone installer from the GCP docs and restart your shell).*
2. Authenticate your user account:
   ```powershell
   gcloud auth login
   ```
3. Generate the application default credentials file:
   ```powershell
   gcloud auth application-default login
   ```
4. Set the active project:
   ```powershell
   gcloud config set project causal-hour-494002-e9
   ```
5. Set the quota project for billing:
   ```powershell
   gcloud auth application-default set-quota-project causal-hour-494002-e9
   ```

---

## 🏃 Running the Security Reviewer

### Run the Pipeline (PowerShell)
To run the automated security reviewer on the sample target, set the `PYTHONPATH` environment variable and run the main entry point:

```powershell
$env:PYTHONPATH="src"
uv run python -m security_assignment.main .\sample_target
```

If you are using **Windows Command Prompt (cmd)**:
```cmd
set PYTHONPATH=src
uv run python -m security_assignment.main .\sample_target
```

### Manual Agent Overrides
If you want to bypass the dynamic Planner LLM and run specific predefined agents, use the `--agents` flag:

```powershell
$env:PYTHONPATH="src"
uv run python -m security_assignment.main .\sample_target --agents sast,auth,dependency
```

---

## 🛠 Running the Sample Target

The `sample_target/` folder contains a Node.js Express application used to test the scanner.

1. Navigate to the folder and install Node packages:
   ```powershell
   cd sample_target
   npm install
   ```
2. Start the application:
   ```powershell
   npm start
   ```

---

## 📂 Project Structure & Architecture

```
├── README.md                      # Windows setup and usage guide
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
