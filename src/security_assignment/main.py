import asyncio
import json
import os
import argparse
from dotenv import load_dotenv
from google.antigravity import Agent, LocalAgentConfig
from google.antigravity.hooks import policy

# Load environment variables from a .env file
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
PROJECT_ID = "security-assignment-reviewer"
LOCATION = "us-central1"

async def run_agent_phase(config: LocalAgentConfig, prompt: str) -> str:
    """
    Executes a clean, direct agent session for a given configuration and prompt.
    With the Pro plan, we run the session directly without artificial delays.
    """
    async with Agent(config) as agent:
        res = await agent.chat(prompt)
        return await res.text()

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
        system_instructions=RECON_INSTRUCTIONS,
        tools=[run_semgrep_sast],
        policies=[policy.allow_all()]
    )
    
    recon_prompt = f"Analyze the repository structure of '{abs_repo_path}'. Provide a brief summary of the architecture and entrypoints."
    recon_text = await run_agent_phase(recon_config, recon_prompt)
    print(f"    - Recon completed. Summary length: {len(recon_text)} characters.")
    
    # ----------------------------------------------------
    # Step 2: SAST & Secrets Phase
    # ----------------------------------------------------
    print("[+] Starting Static Analysis & Secrets Scanning Phase...")
    sast_config = LocalAgentConfig(
        project=PROJECT_ID,
        location=LOCATION,
        system_instructions=SAST_INSTRUCTIONS,
        tools=[run_semgrep_sast, detect_secrets_gitleaks],
        policies=[policy.allow_all()]
    )
    
    sast_prompt = f"Review the codebase: '{abs_repo_path}'. Call your tools 'run_semgrep_sast' and 'detect_secrets_gitleaks' on '{abs_repo_path}'. Return JSON with a 'vulnerabilities' array."
    sast_text = await run_agent_phase(sast_config, sast_prompt)
    print(f"    - SAST Analysis completed.")
    
    # Parse the output, handling potential markdown code blocks
    findings_json = {}
    try:
        clean_json = sast_text.strip()
        if clean_json.startswith("```json"):
            clean_json = clean_json[7:-3]
        findings_json = json.loads(clean_json)
    except json.JSONDecodeError:
        print("    [!] Warning: SAST agent did not return pure JSON. Trying to recover.")
        findings_json = {"vulnerabilities": [{"title": "Raw Output", "description": sast_text}]}

    # ----------------------------------------------------
    # Step 3: Dependency Analysis Phase
    # ----------------------------------------------------
    print("[+] Starting Dependency Analysis Phase...")
    dep_config = LocalAgentConfig(
        project=PROJECT_ID,
        location=LOCATION,
        system_instructions=DEPENDENCY_INSTRUCTIONS,
        tools=[scan_dependencies_trivy],
        policies=[policy.allow_all()]
    )
    
    dep_prompt = f"Audit dependency security for the workspace: '{abs_repo_path}'. Call 'scan_dependencies_trivy' on '{abs_repo_path}' and summarize."
    dep_text = await run_agent_phase(dep_config, dep_prompt)
    print(f"    - Dependency Scan completed.")

    # ----------------------------------------------------
    # Step 4: Verification Phase (DAST/Sandbox)
    # ----------------------------------------------------
    print("[+] Starting Verification Phase...")
    verified_findings = []
    
    verifier_config = LocalAgentConfig(
        project=PROJECT_ID,
        location=LOCATION,
        system_instructions=VERIFICATION_INSTRUCTIONS,
        policies=[policy.allow_all()]
    )

    for finding in findings_json.get("vulnerabilities", []):
        finding_str = json.dumps(finding)
        print(f"    - Verifying finding: {finding.get('title', 'Unknown')}")
        verification_prompt = f"Analyze this finding and generate a regression test payload for it: {finding_str}. Return JSON with 'verified' (true/false) and 'poc_code' (string)."
        
        ver_text = await run_agent_phase(verifier_config, verification_prompt)
        
        try:
            clean_ver = ver_text.strip()
            if clean_ver.startswith("```json"):
                clean_ver = clean_ver[7:-3]
            verification_data = json.loads(clean_ver)
            
            if verification_data.get("verified") == True:
                finding["poc_test_code"] = verification_data.get("poc_code")
                finding["status"] = "VERIFIED"
                verified_findings.append(finding)
            else:
                finding["status"] = "UNVERIFIED (False Positive Rejected)"
        except json.JSONDecodeError:
            finding["status"] = "UNVERIFIED"

    # ----------------------------------------------------
    # Step 5: Reporting Phase
    # ----------------------------------------------------
    print("[+] Starting Reporting Phase...")
    report_config = LocalAgentConfig(
        project=PROJECT_ID,
        location=LOCATION,
        system_instructions=REPORTING_INSTRUCTIONS,
        policies=[policy.allow_all()]
    )
    
    report_text = await run_agent_phase(report_config, f"Consolidate these verified vulnerabilities: {json.dumps(verified_findings)} and dependency issues: {dep_text} into a Markdown report.")

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
