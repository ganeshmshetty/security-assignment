import asyncio
import json
import os
import argparse
from typing import List, Any
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from google.antigravity import Agent, LocalAgentConfig
from google.antigravity.hooks import policy

# Load environment variables from a .env file if it exists
load_dotenv()

# Import custom tools and agent prompts
from security_assignment.tools.scanners import (
    run_semgrep_sast,
    detect_secrets_gitleaks,
    scan_dependencies_trivy
)
from security_assignment.agents.prompts import (
    RECON_INSTRUCTIONS,
    SAST_INSTRUCTIONS,
    DEPENDENCY_INSTRUCTIONS,
    VERIFICATION_INSTRUCTIONS,
    REPORTING_INSTRUCTIONS
)

# Common configuration settings
PROJECT_ID = "causal-hour-494002-e9"
LOCATION = "global"  # Gemini Enterprise Agent Platform uses global location
MODEL_NAME = "gemini-3.5-flash"  # Default thinking model

# ----------------------------------------------------
# Pydantic Schemas for Structured Agent Outputs
# ----------------------------------------------------

class VulnerabilityFinding(BaseModel):
    title: str = Field(description="Title of the hypothesized vulnerability")
    description: str = Field(description="Detailed explanation of the vulnerability and data flow path")
    severity: str = Field(description="Severity (e.g. CRITICAL, HIGH, MEDIUM, LOW)")
    cwe_id: int = Field(description="CWE ID mapping (integer)")
    file: str = Field(description="Target file name")
    line_start: int = Field(description="Starting line number")
    line_end: int = Field(description="Ending line number")

class SASTFindings(BaseModel):
    vulnerabilities: List[VulnerabilityFinding]

class VerificationResult(BaseModel):
    verified: bool = Field(description="Whether the vulnerability was verified as a true positive")
    poc_code: str = Field(description="Regression test code payload proving the vulnerability")


async def run_agent_phase_text(config: LocalAgentConfig, prompt: str) -> str:
    """
    Executes an agent session and returns the raw conversational text response.
    """
    async with Agent(config) as agent:
        res = await agent.chat(prompt)
        return await res.text()

async def run_agent_phase_structured(config: LocalAgentConfig, prompt: str) -> Any:
    """
    Executes an agent session and returns the structured output (dict)
    enforced by the configuration's response_schema.
    """
    async with Agent(config) as agent:
        res = await agent.chat(prompt)
        return await res.structured_output()

async def run_security_pipeline(repo_path: str):
    print(f"[*] Starting Orchestrated AI Security Review on: {repo_path}")

    # Ensure the path is absolute
    abs_repo_path = os.path.abspath(repo_path)

    # ----------------------------------------------------
    # Step 1: Reconnaissance Phase
    # ----------------------------------------------------
    print("[+] Starting Reconnaissance Phase...")
    recon_config = LocalAgentConfig(
        project=PROJECT_ID,
        location=LOCATION,
        vertex=True,
        model=MODEL_NAME,
        system_instructions=RECON_INSTRUCTIONS,
        tools=[run_semgrep_sast],
        policies=[policy.allow_all()]
    )
    
    recon_prompt = f"Analyze the repository structure of '{abs_repo_path}'. Provide a brief summary of the architecture and entrypoints."
    recon_text = await run_agent_phase_text(recon_config, recon_prompt)
    print(f"    - Recon completed. Summary length: {len(recon_text)} characters.")
    
    # ----------------------------------------------------
    # Step 2: SAST & Secrets Phase
    # ----------------------------------------------------
    print("[+] Starting Static Analysis & Secrets Scanning Phase...")
    sast_config = LocalAgentConfig(
        project=PROJECT_ID,
        location=LOCATION,
        vertex=True,
        model=MODEL_NAME,
        system_instructions=SAST_INSTRUCTIONS,
        tools=[run_semgrep_sast, detect_secrets_gitleaks],
        policies=[policy.allow_all()],
        response_schema=SASTFindings  # Enforce structured output via Pydantic model
    )
    
    sast_prompt = f"Review the codebase: '{abs_repo_path}'. Call your tools 'run_semgrep_sast' and 'detect_secrets_gitleaks' on '{abs_repo_path}'. Return the structured vulnerabilities findings list."
    findings = await run_agent_phase_structured(sast_config, sast_prompt)
    print(f"    - SAST Analysis completed.")
    
    # Format findings list from dictionary
    findings_list = []
    if findings and isinstance(findings, dict) and "vulnerabilities" in findings:
        for v in findings["vulnerabilities"]:
            if isinstance(v, dict):
                findings_list.append({
                    "title": v.get("title", "Unknown"),
                    "description": v.get("description", ""),
                    "severity": v.get("severity", "MEDIUM"),
                    "cwe_id": v.get("cwe_id", 0),
                    "file": v.get("file", ""),
                    "line_start": v.get("line_start", 0),
                    "line_end": v.get("line_end", 0)
                })

    # ----------------------------------------------------
    # Step 3: Dependency Analysis Phase
    # ----------------------------------------------------
    print("[+] Starting Dependency Analysis Phase...")
    dep_config = LocalAgentConfig(
        project=PROJECT_ID,
        location=LOCATION,
        vertex=True,
        model=MODEL_NAME,
        system_instructions=DEPENDENCY_INSTRUCTIONS,
        tools=[scan_dependencies_trivy],
        policies=[policy.allow_all()]
    )
    
    dep_prompt = f"Audit dependency security for the workspace: '{abs_repo_path}'. Call 'scan_dependencies_trivy' on '{abs_repo_path}' and summarize."
    dep_text = await run_agent_phase_text(dep_config, dep_prompt)
    print(f"    - Dependency Scan completed.")

    # ----------------------------------------------------
    # Step 4: Verification Phase (DAST/Sandbox)
    # ----------------------------------------------------
    print("[+] Starting Verification Phase...")
    verified_findings = []
    
    verifier_config = LocalAgentConfig(
        project=PROJECT_ID,
        location=LOCATION,
        vertex=True,
        model=MODEL_NAME,
        system_instructions=VERIFICATION_INSTRUCTIONS,
        policies=[policy.allow_all()],
        response_schema=VerificationResult  # Enforce verification results schema
    )

    for finding in findings_list:
        finding_str = json.dumps(finding)
        print(f"    - Verifying finding: {finding.get('title', 'Unknown')}")
        verification_prompt = f"Analyze this finding and generate a regression test payload for it: {finding_str}. Return the structured verification output."
        
        verification_data = await run_agent_phase_structured(verifier_config, verification_prompt)
        
        if verification_data and isinstance(verification_data, dict) and verification_data.get("verified") == True:
            finding["poc_test_code"] = verification_data.get("poc_code", "")
            finding["status"] = "VERIFIED"
            verified_findings.append(finding)
        else:
            finding["status"] = "UNVERIFIED (False Positive Rejected)"

    # ----------------------------------------------------
    # Step 5: Reporting Phase
    # ----------------------------------------------------
    print("[+] Starting Reporting Phase...")
    report_config = LocalAgentConfig(
        project=PROJECT_ID,
        location=LOCATION,
        vertex=True,
        model=MODEL_NAME,
        system_instructions=REPORTING_INSTRUCTIONS,
        policies=[policy.allow_all()]
    )
    
    report_text = await run_agent_phase_text(report_config, f"Consolidate these verified vulnerabilities: {json.dumps(verified_findings)} and dependency issues: {dep_text} into a Markdown report.")

    output_path = os.path.join(abs_repo_path, "SECURITY_ASSIGNMENT_REPORT.md")
    with open(output_path, "w") as f:
        f.write(report_text)
    print(f"[*] Security Review Complete. Report saved to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Orchestrated AI Security Reviewer (SecurityAssignment)")
    parser.add_argument("path", help="Path to the repository to scan")
    args = parser.parse_args()
    
    asyncio.run(run_security_pipeline(args.path))

if __name__ == "__main__":
    main()
