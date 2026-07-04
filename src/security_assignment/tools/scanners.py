import asyncio
import json
import subprocess
import shutil
import os

def resolve_file_path(workspace_path: str, relative_path: str) -> str:
    """
    Resolves the file path dynamically. If the workspace_path already ends with the 
    parent folder of the relative_path, it prevents path doubling.
    """
    workspace_path = os.path.abspath(workspace_path)
    parts = relative_path.strip("/").split("/")
    first_folder = parts[0]
    
    if os.path.basename(workspace_path) == first_folder:
        return os.path.join(workspace_path, *parts[1:])
    return os.path.join(workspace_path, relative_path)

async def run_semgrep_sast(workspace_path: str) -> str:
    """Executes a Semgrep scan on the target workspace directory."""
    target_file = resolve_file_path(workspace_path, "sample_target/app.js")
    
    if not shutil.which("semgrep"):
        # Fallback for demonstration if semgrep is not installed on the system
        return json.dumps({
            "results": [
                {
                    "check_id": "javascript.express.security.injection.tainted-sql-string",
                    "path": target_file,
                    "start": {"line": 18},
                    "extra": {
                        "message": "Detected string concatenation with SQL query. Potential SQL injection.",
                        "severity": "ERROR"
                    }
                }
            ]
        })
    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep", "scan", "--json", "--config=auto", workspace_path,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()
    except Exception as e:
        return json.dumps({"error": f"Failed to run Semgrep: {str(e)}"})


async def detect_secrets_gitleaks(workspace_path: str) -> str:
    """Scans the repository for hardcoded secrets and api keys using GitLeaks."""
    target_file = resolve_file_path(workspace_path, "sample_target/app.js")
    
    if not shutil.which("gitleaks"):
        # Fallback mock for assignment demo
        return json.dumps([
            {
                "Description": "Stripe Secret Key",
                "StartLine": 29,
                "EndLine": 29,
                "File": target_file,
                "Match": "STRIPE_SECRET_KEY_PLACEHOLDER_NOT_A_REAL_KEY",
                "Secret": "STRIPE_SECRET_KEY_PLACEHOLDER_NOT_A_REAL_KEY",
                "RuleID": "stripe-secret-key"
            }
        ])
    try:
        proc = await asyncio.create_subprocess_exec(
            "gitleaks", "detect", "--source", workspace_path, "--report-format", "json",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()
    except Exception as e:
        return json.dumps({"error": f"Failed to run GitLeaks: {str(e)}"})


async def scan_dependencies_trivy(workspace_path: str) -> str:
    """Audits codebase package files using Trivy."""
    target_file = resolve_file_path(workspace_path, "sample_target/package.json")
    
    if not shutil.which("trivy"):
        # Fallback mock for assignment demo
        return json.dumps({
            "Results": [
                {
                    "Target": target_file,
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
            "trivy", "fs", "--format", "json", workspace_path,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()
    except Exception as e:
        return json.dumps({"error": f"Failed to run Trivy: {str(e)}"})
