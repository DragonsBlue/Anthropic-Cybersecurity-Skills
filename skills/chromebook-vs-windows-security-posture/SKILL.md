---
name: chromebook-vs-windows-security-posture
description: >
  Comparative security posture assessment and management guide for K-12 districts
  running Chromebooks for students and Windows devices for staff. Covers policy
  enforcement, threat surface differences, compliance alignment, and unified
  visibility across Google Admin Console and Microsoft Intune/Entra ID.
domain: cybersecurity
subdomain: endpoint-security
tags:
  - chromebook
  - windows
  - intune
  - google-admin-console
  - entra-id
  - autopilot
  - defender-for-endpoint
  - sentinel
  - cybernut
  - k12
  - ferpa
  - zero-trust
  - cis-controls
version: "1.0"
author: DragonsBlue
license: MIT
standards:
  - CIS Controls v8
  - NIST SP 800-124 Rev 2
  - NIST CSF 2.0
  - FERPA
  - CIPA
mitre_attack:
  - T1078 (Valid Accounts)
  - T1566 (Phishing)
  - T1199 (Trusted Relationship)
  - T1530 (Data from Cloud Storage)
---

# Chromebook vs Windows Security Posture (K-12)

## Overview

Most K-12 districts run a split device environment — Chromebooks for students,
Windows for staff. This creates two distinct security surfaces, two management
planes, and two compliance scopes that must be unified under a single security
posture. This skill covers assessment, hardening, monitoring, and incident
response across both platforms as they exist in your environment:

| Segment | Platform | Management | Identity |
|---|---|---|---|
| Students | ChromeOS | Google Admin Console | Google Workspace |
| Staff | Windows 11 | Intune + Autopilot | Entra ID (Azure AD) |
| Security | Both | Defender for Endpoint + Sentinel + CyberNut | Entra ID |

---

## Prerequisites

- Google Admin Console access (Super Admin or Device Admin role)
- Microsoft Intune / Endpoint Manager access
- Microsoft Entra ID (Global Admin or Security Admin)
- Microsoft Defender for Endpoint P1/P2 licensed for staff devices
- Microsoft Sentinel workspace configured
- CyberNut tenant access
- Familiarity with CIS Controls v8 and FERPA data handling requirements

---

## Key Concepts

### The Two-Surface Problem

Chromebooks and Windows devices have fundamentally different threat models in K-12:

**ChromeOS (Student Devices)**
- Verified Boot — OS integrity checked at every startup
- Read-only OS partition — malware can't persist across reboot
- Sandboxed browser tabs — compromises are contained
- Primary risk: **account-based attacks** (stolen Google credentials,
  unauthorized app installs, policy bypass via developer mode)
- FERPA risk: student data in Google Workspace, Drive sharing misconfigurations

**Windows (Staff Devices)**
- Full OS attack surface — malware can persist, escalate privilege, move laterally
- Primary risk: **phishing → credential theft → ransomware / data exfiltration**
- FERPA risk: student records in local files, mapped drives, email attachments
- Higher value target — staff accounts have access to SIS, HR systems, financial data

### Zero Trust Alignment

| Zero Trust Pillar | Chromebook Control | Windows Control |
|---|---|---|
| Identity | Google SSO + 2SV enforcement | Entra ID MFA + Conditional Access |
| Device Health | ChromeOS verified boot + enrollment | Intune compliance policy + Defender |
| Least Privilege | OU-based policy, app allowlist | Entra ID PIM, local admin removal |
| Data Protection | Drive DLP, sharing restrictions | Purview DLP, Defender for O365 |
| Visibility | Admin Console audit logs | Sentinel + Defender XDR |

---

## Implementation Steps

### Step 1: Baseline Security Assessment

Before hardening, establish your current posture on both platforms.

**Google Admin Console — Chromebook Baseline**
```
Admin Console → Devices → Chrome → Settings
Check:
  □ Enrollment enforcement: Forced re-enrollment ON
  □ Developer mode: Blocked (not allowed for students)
  □ Guest mode: Disabled
  □ Verified Access: Enabled
  □ Safe Browsing: Enabled (Enhanced preferred)
  □ Chrome updates: Auto-update ON, update deadline set
  □ Extensions: Allowlist enforced (no unrestricted install)
  □ BeyondCorp / Certificate-based access: Configured if applicable
```

**Intune — Windows Staff Device Baseline**
```
Intune → Devices → Compliance Policies
Check:
  □ BitLocker: Required
  □ Secure Boot: Required
  □ Defender Antivirus: Required (Real-time protection ON)
  □ Firewall: Required
  □ Minimum OS version: Windows 11 22H2 or later
  □ Device Health Attestation: Enabled
  □ Password complexity: Enforced
  □ Local admin accounts: Removed via Intune (use LAPS)
```

**Entra ID — Identity Baseline (Applies to Staff)**
```
Entra ID → Security → Conditional Access
Check:
  □ MFA required for all users (no exceptions)
  □ Block legacy authentication protocols
  □ Require compliant device for M365 access
  □ Named locations configured (district IP ranges)
  □ Sign-in risk policy: Medium+ → MFA challenge
  □ User risk policy: High → force password reset
```

---

### Step 2: Harden Chromebook Fleet (Student Devices)

Apply these settings in Google Admin Console via OU structure.
Recommended OU layout: `Students → [Grade Band] → [School]`

**Device Policies (Devices → Chrome → Settings → Device)**
```
Enrollment:
  - Forced re-enrollment: Enabled
  - Asset tracking: Enabled (annotate with asset tag)

Sign-in:
  - Restrict sign-in to district domain: yourdomain.org
  - Guest browsing: Disabled
  - Add person: Disabled (no personal Google accounts)

Updates:
  - Auto-update: Always autoupdate
  - Rollback to target version: Disabled
  - Update deadline: 4 weeks (forces update if user ignores)
```

**User/Browser Policies (Devices → Chrome → Settings → Users & Browsers)**
```
Security:
  - Safe Browsing: Enhanced protection
  - Password manager: Disabled (use district SSO)
  - Incognito mode: Disabled for students
  - Developer tools: Disabled

Extensions:
  - Force-install approved extensions only
  - Block all extensions except allowlisted
  - Key extensions to force-install:
      Securly / Contentkeeper / GoGuardian (web filter)
      Google Cast (if used in classrooms)

Printing:
  - Restrict to district-managed printers only
```

**CIS Control Alignment:**
- CIS Control 4 (Secure Configuration) — enforced via OU policy
- CIS Control 9 (Email/Browser Protection) — Safe Browsing + extension control
- CIS Control 18 (Awareness Training) — CyberNut covers this layer

---

### Step 3: Harden Windows Staff Devices

**Intune Configuration Profiles**

Create and assign these profiles to your staff device group:

```
Profile 1: Security Baseline (use Microsoft's built-in Windows 11 Security Baseline)
  Intune → Endpoint Security → Security Baselines → Windows 11 Security Baseline
  Assign to: All Staff Devices group

Profile 2: BitLocker
  Intune → Endpoint Security → Disk Encryption → BitLocker
  Settings:
    - Require device encryption: Yes
    - Require storage card encryption: Yes
    - BitLocker recovery key: Escrow to Entra ID

Profile 3: Microsoft Defender Antivirus
  Intune → Endpoint Security → Antivirus
  Settings:
    - Cloud-delivered protection: Enabled
    - Automatic sample submission: Enabled
    - Real-time protection: Enabled
    - PUA protection: Audit → then Block after 30 days

Profile 4: Firewall
  Intune → Endpoint Security → Firewall
  Settings:
    - Domain/Private/Public: All ON
    - Block inbound by default
    - Allow outbound by default

Profile 5: Remove Local Admin Rights
  Intune → Devices → Scripts (PowerShell)
  Script: Remove local admin rights, deploy LAPS
  Note: Use Windows LAPS (built into Windows 11) — configure via Intune
```

**Autopilot Considerations**
```
Ensure new staff devices:
  - Zero-touch enrolled via Autopilot
  - Join Entra ID (hybrid or cloud-only depending on your setup)
  - Receive all compliance/config profiles at first login
  - Assigned to correct user group before deployment
```

---

### Step 4: Unify Visibility — Defender + Sentinel

This is where your two platforms come together in a single pane of glass.

**Defender for Endpoint (Staff Windows Devices)**
```
security.microsoft.com → Endpoints → Device Inventory
Verify:
  □ All staff devices onboarded and showing "Active"
  □ No devices showing "Misconfigured" or "Inactive"
  □ Risk level distribution: Target = Low for all staff devices
  □ Alert queue reviewed daily (set up email digest)
```

**Defender for Office 365 (Staff Email — Phishing Coverage)**
```
security.microsoft.com → Email & Collaboration → Threat Explorer
Weekly checks:
  □ Phishing emails delivered (should be 0 — tune if not)
  □ Malware detections
  □ Impersonation attempts targeting staff
Configure:
  □ Attack Simulation Training → run quarterly phishing sim
  □ Safe Links: Enabled for staff
  □ Safe Attachments: Enabled, Dynamic Delivery
```

**Microsoft Sentinel (SIEM — Unified Alerting)**
```
Recommended Data Connectors to enable:
  □ Microsoft Entra ID (sign-in + audit logs)
  □ Microsoft Defender XDR
  □ Office 365 (Exchange, SharePoint, Teams activity)
  □ DNS (if applicable)

Key Analytics Rules to create/enable:
  □ Multiple failed MFA attempts (staff accounts)
  □ Sign-in from unfamiliar country
  □ Mass file download from SharePoint
  □ Impossible travel alert
  □ New device enrollment outside business hours
```

**CyberNut (Security Awareness)**
```
Use CyberNut for:
  □ Monthly phishing simulations → staff
  □ Annual FERPA awareness training → all staff
  □ New hire onboarding security training
  □ Reporting dashboard → share with administration quarterly
Tie results to Sentinel: High-risk clickers → watchlist in Sentinel
```

---

### Step 5: FERPA Compliance Alignment

Both platforms touch student data — here's where FERPA risk lives on each.

**Chromebook / Google Workspace FERPA Risks**
```
High Risk:
  - Student Drive files shared publicly or with personal accounts
  - Google Meet recordings stored without access controls
  - Classroom data exported by students to personal accounts

Mitigations:
  Admin Console → Apps → Google Workspace → Drive & Docs
    □ Sharing outside domain: Disabled for students
    □ Shared drive creation: Admins only
    □ Download/print/copy for commenters: Disabled
  Admin Console → Reporting → Audit → Drive
    □ Review external share events weekly
```

**Windows / M365 FERPA Risks**
```
High Risk:
  - Student data in staff email attachments sent externally
  - SharePoint/OneDrive sites shared with external parties
  - USB drives exfiltrating student records

Mitigations:
  Purview → Data Loss Prevention
    □ Create policy: Block external sharing of SSN, DOB, student ID patterns
    □ Scope: Exchange, SharePoint, OneDrive, Teams
  Intune → Endpoint Security
    □ Block USB removable storage (or audit + alert)
  Conditional Access
    □ Block personal/unmanaged devices from accessing student data systems
```

---

### Step 6: Incident Response — Split Environment

**Scenario: Compromised Student Chromebook Account**
```
1. Identify → Google Admin Console → Reports → Audit → Login
   Look for: Unusual login time, unfamiliar location, suspicious OAuth grants
2. Contain →
   Admin Console → Users → [Student] → Reset Sign-in Cookies (forces re-auth)
   Admin Console → Users → [Student] → Suspend account if needed
3. Investigate →
   Review Drive audit log for data access/sharing during compromise window
   Check for OAuth apps granted access → revoke suspicious grants
4. Recover →
   Force password reset
   Review and remove unauthorized app authorizations
   Re-enroll device if developer mode was enabled
5. Document → Log under FERPA breach assessment:
   Was student PII accessed? If yes, escalate per district breach policy.
```

**Scenario: Compromised Staff Windows Account**
```
1. Identify → Sentinel alert OR Defender Identity alert
   Signs: Impossible travel, MFA fatigue attack, mass email send
2. Contain →
   Entra ID → Users → [Staff] → Revoke all sessions
   Entra ID → Users → [Staff] → Disable account
   Intune → Devices → [Staff Device] → Remote Lock or Wipe if needed
3. Investigate →
   Defender for Endpoint → Device timeline → review last 48-72 hours
   Sentinel → KQL query for all activity from compromised UPN
   Defender for O365 → Message Trace → review sent/received during window
4. Recover →
   Reset credentials + re-register MFA
   Re-enable account after verification
   Review inbox rules for attacker-planted forwarding rules
5. FERPA Assessment →
   Did compromised account have access to student records?
   If SIS access present → mandatory breach review
```

---

## Red Flags & Indicators of Compromise

### Chromebook (Student)
- Developer mode enabled on enrolled device
- Sign-in from outside district domain
- Bulk Google Drive sharing to external addresses
- Extension installed outside approved allowlist
- Multiple failed enrollment attempts

### Windows (Staff)
- MFA prompt flood (MFA fatigue attack in progress)
- Sign-in from Tor exit node or anonymous VPN
- Large SharePoint/OneDrive download in short timeframe
- New inbox forwarding rule created (common post-compromise)
- Defender alert: credential dumping tool (Mimikatz, etc.)
- Autopilot device enrolled outside normal hours

---

## Tools & Resources

| Tool | Purpose | URL |
|---|---|---|
| Google Admin Console | Chromebook MDM + policy | admin.google.com |
| Microsoft Intune | Windows MDM + compliance | intune.microsoft.com |
| Microsoft Entra ID | Identity + Conditional Access | entra.microsoft.com |
| Microsoft Defender XDR | Endpoint + email security | security.microsoft.com |
| Microsoft Sentinel | SIEM + SOAR | portal.azure.com → Sentinel |
| CyberNut | Security awareness training | Your CyberNut tenant |
| CIS Controls v8 | Security benchmark | cisecurity.org/controls |
| NIST SP 800-124 Rev 2 | Mobile device security | csrc.nist.gov |
| Google BeyondCorp | Zero Trust for ChromeOS | cloud.google.com/beyondcorp |

---

## Validation Checklist

Use this quarterly to confirm posture across both platforms.

**Chromebook (Google Admin Console)**
- [ ] All enrolled devices on latest ChromeOS version (within 1 major release)
- [ ] Zero devices with developer mode enabled
- [ ] Extension allowlist enforced — no unapproved extensions in fleet
- [ ] External Drive sharing disabled for student OUs
- [ ] Forced re-enrollment active

**Windows (Intune + Entra ID)**
- [ ] All staff devices compliant in Intune (0 non-compliant)
- [ ] BitLocker enabled on 100% of staff devices (verify in Intune report)
- [ ] Local admin rights removed from all standard staff accounts
- [ ] MFA enforced via Conditional Access — no exceptions
- [ ] Legacy auth blocked (check Entra sign-in logs for legacy auth attempts)
- [ ] All staff devices active in Defender for Endpoint

**Unified**
- [ ] Sentinel analytics rules active and alerting
- [ ] CyberNut phishing simulation run within last 90 days
- [ ] FERPA data sharing audit completed (Drive + SharePoint)
- [ ] Incident response runbook reviewed by IT team
- [ ] No open High/Critical alerts in Defender XDR queue

---

## References

- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [NIST SP 800-124 Rev 2 — Guidelines for Managing Mobile Devices](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
- [Microsoft Intune Security Baselines](https://learn.microsoft.com/en-us/mem/intune/protect/security-baselines)
- [Google ChromeOS Security Whitepaper](https://chromeos.google/intl/en_us/for-business/security/)
- [Microsoft Entra Conditional Access Best Practices](https://learn.microsoft.com/en-us/entra/identity/conditional-access/best-practices)
- [FERPA — U.S. Department of Education](https://studentprivacy.ed.gov/)
- [Microsoft Sentinel Detection Templates](https://github
