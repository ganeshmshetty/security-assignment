import streamlit as st
import asyncio
import json
import os
import sys

# Ensure 'src' is in python search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

from security_assignment.main import (
    build_agent_config,
    run_structured,
    run_text,
    run_sast_agent,
    run_dependency_agent,
    run_specialized_agent,
    run_dynamic_agent,
    run_verification_agent,
    RECON_INSTRUCTIONS,
    StackProfile,
    PLANNER_INSTRUCTIONS,
    ExecutionPlan,
    PREDEFINED_AGENT_DESCRIPTIONS,
    PREDEFINED_AGENT_REGISTRY,
    TOOL_REGISTRY,
    REPORTING_INSTRUCTIONS,
)
from security_assignment.tools.scanners import run_semgrep_sast


# Page configuration
st.set_page_config(
    page_title="AI Security Reviewer",
    
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=Space+Grotesk:wght@400;500;700&display=swap');

/* Typography overrides */
html, body, [class*="css"] {
    font-family: 'Outfit', sans-serif;
}

code, pre {
    font-family: 'Space Grotesk', monospace !important;
}

/* Header style banner */
.header-banner {
    background: #0f172a;
    padding: 2.5rem;
    border-radius: 8px;
    border: 1px solid #1e293b;
    margin-bottom: 2rem;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
}

.header-banner h1 {
    color: #f8fafc;
    font-size: 2.5rem;
    font-weight: 700;
    margin: 0;
    letter-spacing: -0.02em;
}

.header-banner p {
    color: #cbd5e1;
    font-size: 1.1rem;
    margin-top: 0.5rem;
    margin-bottom: 0;
    opacity: 0.9;
}

/* Custom severity badges */
.severity-badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    font-size: 0.8rem;
    font-weight: 700;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    text-align: center;
}

.badge-critical {
    background-color: #fecaca;
    color: #991b1b;
    border: 1px solid #f87171;
}

.badge-high {
    background-color: #ffedd5;
    color: #9a3412;
    border: 1px solid #fb923c;
}

.badge-medium {
    background-color: #fef9c3;
    color: #854d0e;
    border: 1px solid #facc15;
}

.badge-low {
    background-color: #dbeafe;
    color: #1e40af;
    border: 1px solid #60a5fa;
}

/* Highlight box */
.highlight-box {
    background-color: #1e293b;
    border-left: 5px solid #6366f1;
    padding: 1rem 1.5rem;
    border-radius: 4px 8px 8px 4px;
    margin-bottom: 1.5rem;
}

/* surface badge list */
.surface-badge {
    display: inline-flex;
    align-items: center;
    background-color: #0f172a;
    border: 1px solid #334155;
    color: #e2e8f0;
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
    margin-right: 0.5rem;
    margin-bottom: 0.5rem;
    font-size: 0.85rem;
}
</style>
""", unsafe_allow_html=True)

# Main Banner UI
st.markdown("""
<div class="header-banner">
    <h1>Orchestrated AI Security Reviewer</h1>
    <p>Autonomous dynamic multi-agent security assessment engine built on google-antigravity.</p>
</div>
""", unsafe_allow_html=True)

# Session State Initialization
if "scan_completed" not in st.session_state:
    st.session_state.scan_completed = False
if "profile" not in st.session_state:
    st.session_state.profile = None
if "plan" not in st.session_state:
    st.session_state.plan = None
if "raw_findings" not in st.session_state:
    st.session_state.raw_findings = []
if "verified_findings" not in st.session_state:
    st.session_state.verified_findings = []
if "dependency_report" not in st.session_state:
    st.session_state.dependency_report = ""
if "final_report" not in st.session_state:
    st.session_state.final_report = ""

def reset_scan():
    st.session_state.scan_completed = False
    st.session_state.profile = None
    st.session_state.plan = None
    st.session_state.raw_findings = []
    st.session_state.verified_findings = []
    st.session_state.dependency_report = ""
    st.session_state.final_report = ""

# Sidebar controls
st.sidebar.header("Scanning Targets")
target_path = st.sidebar.text_input("Workspace Path", value="./sample_target", help="Path to the directory containing code to scan.")

st.sidebar.subheader("Configuration")
mode = st.sidebar.radio("Orchestration Mode", ["Auto-Plan (Dynamic Orchestration)", "Manual Agent Selection"])

force_agents = None
if mode == "Manual Agent Selection":
    available_agents = list(PREDEFINED_AGENT_REGISTRY.keys())
    force_agents = st.sidebar.multiselect(
        "Select Agents to Run",
        options=["sast", "dependency"] + available_agents,
        default=["sast", "dependency"],
        help="Choose specific predefined agents to execute, bypassing the dynamic planner."
    )

st.sidebar.divider()
start_btn = st.sidebar.button("Start Security Audit", use_container_width=True, type="primary")

if st.sidebar.button("Clear Results", use_container_width=True):
    reset_scan()
    st.success("Results cleared!")
    st.rerun()

# Async Scanner Pipeline function hooked to Streamlit
async def run_streamlit_scan(path: str, forced_agents=None):
    abs_repo_path = os.path.abspath(path)
    if not os.path.exists(abs_repo_path):
        st.error(f"Path '{abs_repo_path}' does not exist.")
        return

    # Reset former results
    reset_scan()
    
    # Progress feedback container
    progress_status = st.status("Initializing security scan...", expanded=True)
    
    try:
        # Phase 1: Reconnaissance
        progress_status.update(label="[1/5] Phase 1: Reconnaissance & Stack Profiling...", state="running")
        profile_raw = await run_structured(
            build_agent_config(RECON_INSTRUCTIONS, tools=[run_semgrep_sast], schema=StackProfile),
            f"Analyze the repository at '{abs_repo_path}'. Walk its files and produce the StackProfile JSON."
        )
        profile = profile_raw if isinstance(profile_raw, dict) else {}
        st.session_state.profile = profile
        progress_status.write("✓ Reconnaissance & Stack Profiling complete.")
        
        # Phase 2: Planning
        progress_status.update(label="[2/5] Phase 2: Planning agent execution...", state="running")
        if forced_agents:
            # Replicate main.py logic for force_agents overrides
            plan = {
                "predefined_agents": [a for a in forced_agents if a not in ["sast", "dependency"]],
                "dynamic_agents": [],
                "rationale": "Manual override specified by the operator"
            }
            # Handle special cases if sast or dependency are chosen
            run_core_sast = "sast" in forced_agents
            run_core_dep = "dependency" in forced_agents
        else:
            registry_desc = json.dumps(PREDEFINED_AGENT_DESCRIPTIONS, indent=2)
            tool_desc = json.dumps(list(TOOL_REGISTRY.keys()), indent=2)
            plan_raw = await run_structured(
                build_agent_config(PLANNER_INSTRUCTIONS, schema=ExecutionPlan),
                f"""You are planning a security audit. Here is the codebase profile:

{json.dumps(profile, indent=2)}

Available predefined specialized agents (select by name):
{registry_desc}

Available tools for new dynamic agents:
{tool_desc}

Decide which predefined agents to run and if there are any novel security surfaces
not covered by the predefined registry, create new dynamic agent specs for them.
"""
            )
            plan = plan_raw if isinstance(plan_raw, dict) else {"predefined_agents": [], "dynamic_agents": []}
            run_core_sast = True
            run_core_dep = True
            
        st.session_state.plan = plan
        progress_status.write(f"✓ Planning complete. Rationale: {plan.get('rationale', 'N/A')}")
        progress_status.write(f"  Predefined agents activated: {plan.get('predefined_agents', [])}")
        if plan.get("dynamic_agents"):
            progress_status.write(f"  Dynamic agents created: {[s.get('name') if isinstance(s, dict) else s for s in plan.get('dynamic_agents', [])]}")

        # Phase 3: Agent Execution (Sequential execution to prevent system resource exhaust / pagefile limits)
        selected_predefined = plan.get("predefined_agents", [])
        dynamic_specs = plan.get("dynamic_agents", [])
        
        total_agents = (1 if run_core_sast else 0) + (1 if run_core_dep else 0) + len(selected_predefined) + len(dynamic_specs)
        progress_status.update(label=f"[3/5] Phase 3: Executing analysis agents (Total: {total_agents} agents)", state="running")
        
        all_findings = []
        dep_text = ""
        agent_idx = 1

        # 3.1: Core SAST
        if run_core_sast:
            progress_status.write(f"  [{agent_idx}/{total_agents}] Running Core SAST Agent...")
            try:
                sast_findings = await run_sast_agent(abs_repo_path)
                progress_status.write(f"  ✓ Core SAST Agent finished. Identified {len(sast_findings)} potential vulnerability pattern(s).")
                for f in sast_findings:
                    f["source_agent"] = "sast"
                    all_findings.append(f)
            except Exception as ex:
                progress_status.write(f"  ❌ Core SAST Agent failed: {str(ex)}")
            agent_idx += 1

        # 3.2: Core Dependency Scanner
        if run_core_dep:
            progress_status.write(f"  [{agent_idx}/{total_agents}] Running Core Dependency Auditor (Trivy)...")
            try:
                dep_text = await run_dependency_agent(abs_repo_path)
                st.session_state.dependency_report = dep_text
                progress_status.write("  ✓ Dependency Auditor completed package scanning.")
            except Exception as ex:
                progress_status.write(f"  ❌ Dependency Auditor failed: {str(ex)}")
            agent_idx += 1

        # 3.3: Predefined Agents
        for p_name in selected_predefined:
            progress_status.write(f"  [{agent_idx}/{total_agents}] Running Predefined Expert: '{p_name}' Agent...")
            if p_name in PREDEFINED_AGENT_REGISTRY:
                try:
                    findings = await run_specialized_agent(p_name, PREDEFINED_AGENT_REGISTRY[p_name], abs_repo_path)
                    progress_status.write(f"  ✓ Predefined '{p_name}' Agent finished. Found {len(findings)} vulnerability candidate(s).")
                    for f in findings:
                        f["source_agent"] = p_name
                        all_findings.append(f)
                except Exception as ex:
                    progress_status.write(f"  ❌ Predefined '{p_name}' Agent failed: {str(ex)}")
            else:
                progress_status.write(f"  Warning: Agent '{p_name}' not registered.")
            agent_idx += 1

        # 3.4: Dynamic Agents
        for d_spec in dynamic_specs:
            spec_dict = dict(d_spec) if not isinstance(d_spec, dict) else d_spec
            name = spec_dict.get("name", "unknown")
            progress_status.write(f"  [{agent_idx}/{total_agents}] Running Custom Dynamic Agent: '{name}'...")
            try:
                findings = await run_dynamic_agent(spec_dict, abs_repo_path)
                progress_status.write(f"  ✓ Dynamic Agent '{name}' finished. Found {len(findings)} vulnerability candidate(s).")
                for f in findings:
                    f["source_agent"] = f"dynamic:{name}"
                    all_findings.append(f)
            except Exception as ex:
                progress_status.write(f"  ❌ Dynamic Agent '{name}' failed: {str(ex)}")
            agent_idx += 1

        st.session_state.raw_findings = all_findings
        progress_status.write(f"✓ Scan phase finished. Total raw vulnerabilities identified: {len(all_findings)}")

        # Phase 4: Verification
        progress_status.update(label=f"[4/5] Phase 4: Verifying {len(all_findings)} finding(s) sequentially...", state="running")
        
        verified_findings = []
        for i, finding in enumerate(all_findings):
            v_title = finding.get('title', 'Untitled')
            v_file = finding.get('file', 'Unknown')
            progress_status.write(f"  [{i+1}/{len(all_findings)}] Verifying '{v_title}' in {os.path.basename(v_file)}...")
            try:
                if i > 0:
                    await asyncio.sleep(3.0)  # Rate pacing
                res = await run_verification_agent(finding)
                if res is not None:
                    progress_status.write(f"    CONFIRMED: '{v_title}' is a true positive. Generated regression PoC.")
                    verified_findings.append(res)
                else:
                    progress_status.write(f"    REJECTED: '{v_title}' identified as false positive.")
            except Exception as ex:
                progress_status.write(f"    Verification error for '{v_title}': {str(ex)}")
                
        st.session_state.verified_findings = verified_findings
        progress_status.write(f"✓ Verification phase complete. Confirmed {len(verified_findings)} true positives / {len(all_findings)} raw findings.")

        # Phase 5: Reporting
        progress_status.update(label="[5/5] Phase 5: Compiling final Security Report...", state="running")
        progress_status.write("  Synthesizing overall markdown security audit report...")
        report_config = build_agent_config(REPORTING_INSTRUCTIONS)
        report_text = await run_text(
            report_config,
            f"Generate a comprehensive Security Audit Report.\n\n"
            f"Stack Profile:\n{json.dumps(profile, indent=2)}\n\n"
            f"Agents Run: {total_agents} total\n\n"
            f"Verified Code Vulnerabilities:\n{json.dumps(verified_findings, indent=2)}\n\n"
            f"Dependency Audit Summary:\n{dep_text}"
        )
        st.session_state.final_report = report_text
        
        output_path = os.path.join(abs_repo_path, "SECURITY_ASSIGNMENT_REPORT.md")
        progress_status.write(f"  Writing final report to: {output_path}")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)
            
        progress_status.update(label="Security Scan Finished Successfully", state="complete")
        st.session_state.scan_completed = True
        
    except Exception as e:
        progress_status.update(label="Pipeline Execution Failed", state="error")
        st.error(f"Error executing security pipeline: {str(e)}")
        import traceback
        st.code(traceback.format_exc())

# Action handler
if start_btn:
    asyncio.run(run_streamlit_scan(target_path, force_agents))

# Output display UI
if st.session_state.scan_completed:
    st.success("Audit complete! Results are loaded below.")
    
    # Main Tabs
    tab_overview, tab_planner, tab_vulns, tab_deps, tab_report = st.tabs([
        "Scan Overview", 
        "Orchestration & Planner", 
        "Verified Vulnerabilities", 
        "Dependency Audit", 
        "Complete Audit Report"
    ])
    
    with tab_overview:
        st.subheader("Codebase Profile Summary")
        profile = st.session_state.profile
        
        # High level metric cards
        col_total, col_verified, col_unverified, col_ratio = st.columns(4)
        total_count = len(st.session_state.raw_findings)
        verified_count = len(st.session_state.verified_findings)
        unverified_count = total_count - verified_count
        ratio = (verified_count / total_count * 100) if total_count > 0 else 0
        
        with col_total:
            st.metric("Total Raw Findings", total_count)
        with col_verified:
            st.metric("Verified Vulnerabilities", verified_count, delta_color="inverse")
        with col_unverified:
            st.metric("False Positives Rejected", unverified_count)
        with col_ratio:
            st.metric("Verification Rate", f"{ratio:.1f}%")
            
        # Detail Columns
        col_left, col_right = st.columns(2)
        
        with col_left:
            st.write("#### Technical Stack")
            st.write(f"**Primary Languages:** {', '.join(profile.get('languages', []))}")
            st.write(f"**Frameworks/Libraries:** {', '.join(profile.get('frameworks', []))}")
            st.write(f"**Main Entry Point Files:**")
            for entry in profile.get("entry_files", []):
                st.code(entry)
                
        with col_right:
            st.write("#### Detected Security Surfaces")
            surfaces = []
            if profile.get("has_database"):
                surfaces.append(f"Database ({profile.get('db_type', 'unknown')})")
            if profile.get("has_auth"):
                surfaces.append("Auth Middleware / Sessions")
            if profile.get("has_payment_api"):
                surfaces.append(f"Payment APIs ({', '.join(profile.get('payment_providers', []))})")
            if profile.get("has_file_uploads"):
                surfaces.append("File Upload System")
            if profile.get("has_external_http"):
                surfaces.append("Outbound HTTP Requests")
            for surf in profile.get("notable_surfaces", []):
                surfaces.append(f"{surf}")
                
            if surfaces:
                for s in surfaces:
                    st.markdown(f'<span class="surface-badge">{s}</span>', unsafe_allow_html=True)
            else:
                st.info("No major security surfaces detected during stack profile.")

    with tab_planner:
        st.subheader("LLM Orchestrator Decisions")
        plan = st.session_state.plan
        
        st.markdown(f"""
        <div class="highlight-box">
            <strong>Planner Rationale:</strong><br/>
            {plan.get('rationale', 'N/A')}
        </div>
        """, unsafe_allow_html=True)
        
        col_pre, col_dyn = st.columns(2)
        with col_pre:
            st.write("#### Activated Predefined Expert Agents")
            pre_agents = plan.get("predefined_agents", [])
            if pre_agents:
                for agent in pre_agents:
                    desc = PREDEFINED_AGENT_DESCRIPTIONS.get(agent, "Specialized review")
                    st.markdown(f"**{agent.capitalize()} Agent**")
                    st.caption(desc)
                    st.markdown("---")
            else:
                st.info("No predefined specialized agents were triggered for this profile.")
                
        with col_dyn:
            st.write("#### Synthesized Dynamic Agents")
            dyn_agents = plan.get("dynamic_agents", [])
            if dyn_agents:
                for agent in dyn_agents:
                    st.markdown(f"**{agent.get('name', 'Dynamic Agent')}**")
                    st.markdown(f"**Focus:** {agent.get('focus', 'N/A')}")
                    st.caption(f"**Trigger Reason:** {agent.get('trigger_reason', 'N/A')}")
                    with st.expander("Show System Prompt instructions"):
                        st.code(agent.get("system_instructions", ""))
                    st.markdown("---")
            else:
                st.info("No custom dynamic agents were needed for novel surfaces.")

    with tab_vulns:
        st.subheader("Verified Code Vulnerabilities")
        verified_vulns = st.session_state.verified_findings
        
        if not verified_vulns:
                        st.success("No code vulnerabilities were confirmed by the verification agent. Clean scan!")
        else:
            for idx, vuln in enumerate(verified_vulns):
                severity = vuln.get("severity", "LOW").upper()
                badge_class = "badge-low"
                if severity == "CRITICAL":
                    badge_class = "badge-critical"
                elif severity == "HIGH":
                    badge_class = "badge-high"
                elif severity == "MEDIUM":
                    badge_class = "badge-medium"
                    
                st.markdown(f"""
                <div style="display:flex; align-items:center; gap:10px; margin-bottom: 5px;">
                    <span class="severity-badge {badge_class}">{severity}</span>
                    <h3 style="margin:0; font-size:1.25rem;">{vuln.get('title')}</h3>
                </div>
                <div style="color: #64748b; font-size: 0.9rem; margin-bottom: 10px;">
                    Affected File: <code>{vuln.get('file')}</code> (Lines {vuln.get('line_start')}-{vuln.get('line_end')}) | CWE-{vuln.get('cwe_id')} | Agent: <em>{vuln.get('source_agent')}</em>
                </div>
                """, unsafe_allow_html=True)
                
                st.write(vuln.get('description'))
                
                poc_code = vuln.get('poc_test_code', '')
                if poc_code:
                    with st.expander("View Proof-of-Concept (PoC) Regression Test", expanded=True):
                        st.code(poc_code, language="python")
                
                st.divider()

    with tab_deps:
        st.subheader("Dependency Security Scan Report (Trivy)")
        dep_report = st.session_state.dependency_report
        if dep_report:
            st.markdown(dep_report)
        else:
            st.info("No dependency findings recorded.")

    with tab_report:
        st.subheader("SECURITY_ASSIGNMENT_REPORT.md")
        st.markdown(st.session_state.final_report)
else:
    st.info("Enter target workspace path and click **Start Security Audit** in the sidebar to begin.")
    
    st.write("### Review Process Overview")
    st.markdown("""
    1. **Reconnaissance & Stack Profiling**: Scans files, determines technology stack, main entrances, and config properties.
    2. **Dynamic Planning**: LLM Agent examines details and configures optimized scanning experts (predefined & dynamic).
    3. **Parallel Execution**: Dispatches multiple SAST and Dependency engines in parallel.
    4. **Sequential Verification**: Attempts to write regression tests/validation logic using the Verification agent to confirm true positives.
    5. **Consolidated Report**: Saves results to `SECURITY_ASSIGNMENT_REPORT.md` inside your target.
    """)
