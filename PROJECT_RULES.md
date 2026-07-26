# REAL_SECURITY_SCANNING_RULES.md

# CyberMind AI - Real Security Scanning Constitution

Version: 1.0

This document defines the mandatory implementation rules for all security scanning features in CyberMind AI.

Every AI coding assistant should follow these rules whenever implementing or modifying any scanning-related functionality.

---

# Mission

CyberMind AI must function as a real defensive cybersecurity platform.

It must never fake scan results.

All analysis must be based on actual evidence collected from real security tools or uploaded data.

---

# Core Principles

## Rule 1

Never generate fictional vulnerabilities.

## Rule 2

Never fabricate CVEs.

## Rule 3

Never fabricate MITRE ATT&CK mappings.

## Rule 4

Never invent attack evidence.

## Rule 5

Always explain uncertainty.

If insufficient evidence exists, clearly state:

> Additional evidence is required before a conclusion can be made.

---

# Network Scanning

The platform should support real network scanning.

Supported engines:

- Nmap
- RustScan
- Masscan (optional)

Supported scan types:

- Host Discovery
- TCP Scan
- UDP Scan
- SYN Scan
- Version Detection
- Service Detection
- OS Detection
- Banner Grabbing
- Safe NSE Scripts

Supported outputs:

- XML
- JSON
- Grepable Output

The AI should only interpret the scan results.

The AI should never simulate scans.

---

# Vulnerability Assessment

Supported scanners:

- OpenVAS / Greenbone
- Nessus (Import Reports)
- Nuclei (Safe Templates)
- Trivy
- Grype

Supported findings:

- CVE
- CVSS
- CWE
- Severity
- Exploit Availability
- Patch Information

The AI should:

- Explain vulnerabilities
- Prioritize remediation
- Estimate business impact
- Suggest mitigation

---

# Web Security

Supported engines:

- OWASP ZAP
- Nikto
- Nuclei

Checks include:

- Missing Security Headers
- HTTPS Configuration
- TLS Configuration
- Cookie Security
- CSP
- HSTS
- X-Frame-Options
- X-Content-Type-Options

The AI should explain every finding.

---

# Container Security

Supported platforms:

- Docker
- Kubernetes

Supported tools:

- Trivy
- kube-bench
- kube-hunter (Authorized environments only)

Supported scans:

- Image Scan
- Filesystem Scan
- Configuration Scan
- Secret Detection
- Dependency Scan

---

# Cloud Security

Supported platforms:

- AWS
- Azure
- Google Cloud

Supported data:

- CloudTrail
- Azure Activity Logs
- Google Cloud Audit Logs

The AI should identify:

- Suspicious Logins
- Permission Changes
- Public Storage
- IAM Misconfigurations

---

# Log Analysis

Supported logs:

- Windows Event Logs
- Linux Syslog
- Apache
- Nginx
- Firewall Logs
- Cisco
- Fortinet
- Palo Alto
- AWS CloudTrail
- Azure Logs
- Google Cloud Logs

The AI should detect:

- Failed Login Attempts
- Brute Force
- Malware Indicators
- Lateral Movement
- Privilege Escalation
- Suspicious Services
- DNS Anomalies
- Persistence Techniques

---

# Threat Intelligence

Supported sources:

- MITRE ATT&CK
- NVD
- CISA KEV
- CVE Database
- CWE
- CAPEC

Optional integrations:

- AbuseIPDB
- VirusTotal
- AlienVault OTX
- Cisco Talos

The AI should enrich findings with verified threat intelligence.

---

# AI Responsibilities

The AI is responsible for:

- Explaining findings
- Mapping MITRE ATT&CK
- CVSS interpretation
- Executive summaries
- Technical summaries
- Risk scoring
- Prioritized remediation
- Compliance guidance

The AI must not:

- Invent vulnerabilities
- Invent CVEs
- Invent exploits
- Invent threat actors
- Invent attack chains

---

# Incident Reports

Every report should include:

- Executive Summary
- Timeline
- Scope
- Evidence
- Indicators of Compromise
- MITRE ATT&CK Mapping
- Vulnerability Summary
- Risk Assessment
- Business Impact
- Root Cause
- Remediation
- Future Recommendations

Export formats:

- PDF
- HTML
- Markdown
- DOCX

---

# Scan Workflow

User

↓

Select Target

↓

Permission Verification

↓

Run Scanner

↓

Collect Results

↓

Normalize Data

↓

Threat Intelligence Correlation

↓

AI Analysis

↓

Risk Scoring

↓

Generate Report

↓

Store History

---

# Authorization

Before every scan:

The platform must verify that:

- The target belongs to the user; or
- The user has explicit authorization.

If authorization cannot be verified:

The scan must not start.

---

# Safe Defaults

Enabled:

- Host Discovery
- Service Detection
- Version Detection
- Safe NSE Scripts
- TLS Inspection
- Header Analysis

Disabled by default:

- Aggressive scans
- High-speed scanning
- Authentication brute force
- Password guessing
- Exploit execution
- Destructive testing

---

# Dashboard

The dashboard should display:

- Security Score
- Critical Alerts
- Open Vulnerabilities
- Active Hosts
- Scan History
- Recent Reports
- Top CVEs
- MITRE Coverage
- Patch Status
- Compliance Status

---

# Scan History

Store:

- Scan Time
- Scanner Used
- Target
- Duration
- Findings
- Reports
- Severity Distribution

Support:

- Search
- Filter
- Export
- Comparison

---

# Compliance

Support references to:

- NIST Cybersecurity Framework
- NIST SP 800-53
- CIS Controls
- OWASP Top 10
- MITRE ATT&CK
- ISO/IEC 27001

---

# Performance

Support:

- Async scanning
- Task queue
- Progress tracking
- Scan cancellation
- Parallel safe jobs
- Result caching

---

# Security

Always:

- Encrypt secrets
- Encrypt API keys
- Validate uploads
- Verify file types
- Sanitize user input
- Rate limit APIs
- Log security events
- Require authentication
- Enforce RBAC

---

# Logging

Log:

- User
- Time
- Target
- Scanner
- Result
- Errors
- Authorization Status

---

# Future Expansion

Architecture should support:

- Multi-Agent AI
- SOC Automation
- SIEM Integration
- SOAR Integration
- Multi-Tenant SaaS
- Plugin System
- Scheduled Scans
- Distributed Workers
- Enterprise Authentication

---

# Final Rule

CyberMind AI is a defensive cybersecurity platform.

Every feature must improve:

- Accuracy
- Reliability
- Security
- Transparency
- Maintainability

The system must never fabricate technical findings or perform actions beyond the user's authorized scope.

Its purpose is to help defenders understand, assess, and improve the security of systems they own or are authorized to test.