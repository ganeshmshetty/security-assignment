# security-assignment

This repository contains the system design document and programmatic implementation of the Orchestrated AI Security Reviewer using the Google Antigravity SDK.

## Project Structure
- [system_design_document.md](file:///Users/ganesh/dev/razorpay_assignment/system_design_document.md): Detailed SDE system design document outlining agent roles, verification sandbox pipeline, findings schema, and safety policy.
- [src/security_assignment/main.py](file:///Users/ganesh/dev/razorpay_assignment/src/security_assignment/main.py): Clean, direct python orchestrator using the `google-antigravity` SDK.
- [src/security_assignment/tools/scanners.py](file:///Users/ganesh/dev/razorpay_assignment/src/security_assignment/tools/scanners.py): CLI tool wrappers with built-in sandbox mock fallbacks.
- [src/security_assignment/agents/prompts.py](file:///Users/ganesh/dev/razorpay_assignment/src/security_assignment/agents/prompts.py): System instructions for specialized sub-agents.
- [safety_policy.json](file:///Users/ganesh/dev/razorpay_assignment/safety_policy.json): Safety boundaries and constraints mapping.
- [sample_target/](file:///Users/ganesh/dev/razorpay_assignment/sample_target/): Vulnerable Node.js target app used for scanning demonstrations.
