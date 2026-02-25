# LinkedIn Launch Post

---

I just open-sourced a database of 611 cybersecurity skills for AI agents.

The problem is straightforward: AI coding agents like Claude Code, GitHub Copilot, and Cursor are transforming software engineering. But when it comes to cybersecurity, they give generic advice instead of the precise, tool-specific knowledge a practitioner would use.

Ask an AI to "analyze this memory dump" and you get a Wikipedia summary. A senior analyst would immediately reach for Volatility 3, run `vol3 -f dump.raw windows.pslist`, check for process hollowing with `windows.malfind`, and extract injected code for YARA scanning. That procedural knowledge is what these skills encode.

What I built:

611 skills across 24 cybersecurity subdomains, each following a structured format:
- YAML frontmatter: tells the agent WHEN to activate (trigger conditions, prerequisites, domain tags)
- Markdown body: the HOW -- step-by-step workflows with exact commands, tool flags, and decision trees
- References to real standards: MITRE ATT&CK technique IDs, NIST controls, CIS benchmarks
- Practitioner helper scripts and filled-in report templates

Coverage spans the full cybersecurity landscape:
Cloud Security (48 skills), Threat Intelligence (43), Web Application Security (41), Threat Hunting (35), Malware Analysis (34), Digital Forensics (34), SOC Operations (33), Network Security (33), Identity & Access Management (33), OT/ICS Security (28), API Security (28), Container Security (26), Vulnerability Management (24), Red Teaming (24), Incident Response (24), Penetration Testing (23), Zero Trust Architecture (17), Phishing Defense (16), Endpoint Security (16), DevSecOps (16), Cryptography (13), Mobile Security (12), Ransomware Defense (5), and Compliance & Governance (5).

The format follows the agentskills.io open standard, so any agent framework can consume these skills.

This is MIT licensed and open for contributions. If you're a security practitioner and you write runbooks, you already know how to write skills. I'm especially looking for contributors in OT/ICS security, mobile security, and compliance.

The future of cybersecurity involves AI agents that genuinely understand the domain -- not as replacements for analysts, but as force multipliers that have instant recall of every tool flag, every MITRE technique, and every standard reference.

Link: https://github.com/mukul975/Anthropic-Cybersecurity-Skills

#cybersecurity #opensource #AI #infosec #threatintelligence #pentesting #DFIR #cloudsecurity
