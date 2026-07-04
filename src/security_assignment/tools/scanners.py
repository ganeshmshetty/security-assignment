import asyncio
import json
import subprocess
import shutil
import os


async def run_semgrep_sast(workspace_path: str) -> str:
    \"\"\"
    Executes a Semgrep SAST scan on the target workspace directory.
    Returns findings as a JSON string. Falls back to mock data if Semgrep is not installed.
    \"\"\"
    exe_path = shutil.which("semgrep")
    if not exe_path:
        # Fallback mock when semgrep is not installed
        return json.dumps({
            "results": [
                {
                    "check_id": "javascript.express.security.injection.tainted-sql-string",
                    "path": os.path.join(workspace_path, "app.js"),
                    "start": {"line": 18},
                    "extra": {
                        "message": "Detected string concatenation with a user-supplied value into an SQL query. This is a potential SQL injection vulnerability.",
                        "severity": "ERROR"
                    }
                }
            ],
            "errors": []
        })
    try:
        proc = await asyncio.create_subprocess_exec(
            exe_path, "scan", "--json", "--config=auto", workspace_path,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip() or json.dumps({"results": [], "errors": []})
    except Exception as e:
        return json.dumps({"error": f"Failed to run Semgrep: {str(e)}", "results": []})


async def detect_secrets_gitleaks(workspace_path: str) -> str:
    \"\"\"
    Scans the repository for hardcoded secrets and API keys using Gitleaks.
    Returns findings as a JSON string. Falls back to mock data if Gitleaks is not installed.
    \"\"\"
    exe_path = shutil.which("gitleaks")
    if not exe_path:
        # Fallback mock when gitleaks is not installed
        return json.dumps([
            {
                "Description": "Stripe Secret Key",
                "StartLine": 29,
                "EndLine": 29,
                "File": os.path.join(workspace_path, "app.js"),
                "Match": "STRIPE_SECRET_KEY_PLACEHOLDER_NOT_A_REAL_KEY",
                "Secret": "STRIPE_SECRET_KEY_PLACEHOLDER_NOT_A_REAL_KEY",
                "RuleID": "stripe-secret-key"
            }
        ])
    try:
        proc = await asyncio.create_subprocess_exec(
            exe_path, "detect", "--source", workspace_path,
            "--report-format", "json", "--no-git",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        raw = stdout.decode().strip()
        # Gitleaks exits non-zero when it finds secrets; we still want the output
        return raw if raw else json.dumps([])
    except Exception as e:
        return json.dumps({"error": f"Failed to run Gitleaks: {str(e)}"})


async def scan_dependencies_trivy(workspace_path: str) -> str:
    \"\"\"
    Audits codebase package manifests using Trivy for known CVEs.
    Returns findings as a JSON string. Falls back to mock data if Trivy is not installed.
    \"\"\"
    exe_path = shutil.which("trivy")
    if not exe_path:
        # Fallback mock when trivy is not installed
        return json.dumps({
            "Results": [
                {
                    "Target": os.path.join(workspace_path, "package.json"),
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2022-29217",
                            "PkgName": "express",
                            "InstalledVersion": "4.18.2",
                            "FixedVersion": "4.18.3",
                            "Severity": "HIGH",
                            "Title": "Express.js potential prototype pollution"
                        }
                    ]
                }
            ]
        })
    try:
        proc = await asyncio.create_subprocess_exec(
            exe_path, "fs", "--format", "json", workspace_path,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip() or json.dumps({"Results": []})
    except Exception as e:
        return json.dumps({"error": f"Failed to run Trivy: {str(e)}", "Results": []})
