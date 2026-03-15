---
name: ferpa-incident-response
description: >
  Incident response playbook for K-12 districts when student PII may have been
  exposed, breached, or improperly disclosed. Covers detection, containment,
  assessment, notification, and documentation requirements under FERPA. Tailored
  for environments where IT owns the privacy response function, with student data
  residing in Infinite Campus, Google Workspace, and Microsoft 365/SharePoint.
domain: cybersecurity
subdomain: compliance-incident-response
tags:
  - ferpa
  - privacy
  - incident-response
  - k12
  - student-data
  - infinite-campus
  - google-workspace
  - microsoft-365
  - sharepoint
  - entra-id
  - sentinel
  - defender
  - data-breach
version: "1.0"
author: DragonsBlue
license: MIT
standards:
  - FERPA (20 U.S.C. § 1232g)
  - NIST SP 800-61 Rev 2 (Incident Response)
  - NIST CSF 2.0
  - CIS Controls v8 (Control 17 — Incident Response)
mitre_attack:
  - T1078 (Valid Accounts)
  - T1530 (Data from Cloud Storage)
  - T1213 (Data from Information Repositories)
  - T1566 (Phishing)
---

# FERPA Incident Response (K-12)

## Overview

FERPA (Family Educational Rights and Privacy Act) governs how student education
records are handled, shared, and protected. When a security incident may have
exposed student PII, IT owns the response — detection through documentation.

This playbook covers the full lifecycle: detecting a potential FERPA incident,
containing the exposure, determining if FERPA was actually violated, notifying
the right people, and documenting everything properly.

**Student PII in your environment lives in:**
| System | Data Type | Risk Level |
|---|---|---|
| Infinite Campus (SIS) | Grades, enrollment, demographics, attendance, IEPs | Critical |
| Google Workspace / Drive | Assignments, teacher notes, student files, Meet recordings | High |
| Microsoft 365 / SharePoint | Staff-created documents with student data, email, Teams | High |
| Staff Windows devices | Local files, downloaded reports, email attachments | Medium-High |

---

## Prerequisites

- Access to Google Admin Console (audit logs)
- Access to Microsoft Purview / Compliance Center
- Access to Microsoft Sentinel and Defender XDR
- Access to Infinite Campus admin panel
- Understanding of what constitutes an "education record" under FERPA
- Contact information for superintendent and district legal counsel

---

## Key Concepts

### What Is a FERPA Incident?

Not every security event is a FERPA incident. A FERPA incident occurs when
**education records** containing student PII are accessed, disclosed, or
exposed to unauthorized parties **without consent**.

**Education records include:** grades, transcripts, disciplinary records,
contact info, IEP/504 documents, attendance, financial aid, assessment results.

**Does NOT include:** directory information (if district has published a
directory info policy), records held only in the personal memory of a teacher,
law enforcement records.

### FERPA vs. Data Breach — Know the Difference

| Situation | FERPA Incident? | Breach? |
|---|---|---|
| Staff accidentally emails student grades to wrong parent | Yes | Maybe |
| Ransomware encrypts SIS but no data confirmed exfiltrated | No | Yes |
| Google Drive folder with class roster shared publicly | Yes | Yes |
| Staff account compromised, had SIS access | Yes — assess scope | Yes |
| Teacher shows student grades on projector accidentally | Yes (minor) | No |
| Vendor accesses student data outside their DSAA scope | Yes | Possibly |

### FERPA Notification Requirements

FERPA does **not** mandate breach notification to parents in the same way
HIPAA does — BUT:
- The district must notify affected families if education records were
  improperly disclosed to a third party
- The U.S. Department of Education must be notified of certain violations
- Many states have their own student privacy laws with stricter notification
  requirements (check your state)
- Districts must maintain a log of all disclosures of education records

---

## Incident Response Phases

---

### Phase 1: DETECT

**Sources that trigger FERPA incident investigation:**

**Automated Alerts (Microsoft Sentinel)**
```
Key analytics rules to have enabled:
  □ Mass download from SharePoint/OneDrive (>50 files in 10 min)
  □ External sharing of files containing PII keywords
  □ Sign-in from high-risk location to M365
  □ Defender DLP policy match — student data pattern detected
  □ Bulk email send from staff account
```

**Manual Reports (most common in K-12)**
```
  □ Staff member reports sending email to wrong recipient
  □ Parent reports receiving another student's information
  □ Teacher reports misconfigured Google Classroom sharing
  □ Staff reports lost/stolen laptop with student files
  □ Vendor reports accidental access to district data
  □ IT discovers publicly accessible SharePoint site with student data
```

**Google Admin Console — Drive Audit**
```
Admin Console → Reporting → Audit and Investigation → Drive log events
Filter by:
  - Event: "Share" with Visibility = "Public on the web" or "Anyone with link"
  - Date range: last 30 days
  - OU: Staff OUs
Flag: Any student-related files shared outside domain
```

**Microsoft Purview — DLP Alerts**
```
compliance.microsoft.com → Data loss prevention → Alerts
Review:
  □ Policy matches for student ID, SSN, DOB patterns
  □ External share events from SharePoint/OneDrive
  □ Email DLP matches (student data sent externally)
```

---

### Phase 2: CONTAIN

Act immediately to stop ongoing exposure. Speed matters here.

**Scenario A: Google Drive / Workspace Exposure**
```
1. Admin Console → Reporting → Drive log → identify the file(s)
2. Admin Console → Users → [Staff Member] → Drive
   → Find shared item → Remove external sharing immediately
3. If public link: Disable link sharing on the file
4. If Google Classroom misconfiguration:
   → Remove external students/accounts from classroom
5. Preserve: Screenshot the sharing settings BEFORE changing them
   (documentation for the incident record)
6. Check: Were the files downloaded by unauthorized party?
   Drive audit log → filter by file name → look for "Download" events
   by accounts outside your domain
```

**Scenario B: Microsoft 365 / SharePoint Exposure**
```
1. compliance.microsoft.com → Content Search → search for affected files
2. SharePoint Admin Center → identify the site/library
   → Site permissions → remove external access
3. If email: Exchange Admin → Message Trace → confirm recipients
   → Cannot unsend, but document what was sent to whom
4. Purview → Data Loss Prevention → confirm scope of policy match
5. If OneDrive: Intune → [Staff Device] → review sync status
   → Disable OneDrive sync if device is lost/stolen
6. Preserve: Export message trace and sharing audit logs before making changes
```

**Scenario C: Infinite Campus Exposure**
```
1. Infinite Campus Admin → System Administration → User Security
   → Review user account activity for compromised/unauthorized access
2. Infinite Campus → Census → check if any data was exported
   (Reports → look for scheduled or ad-hoc exports during incident window)
3. If staff account compromised:
   → Disable IC account immediately
   → Entra ID → revoke all sessions for that user
   → Reset credentials
4. Contact Infinite Campus support if breach involves their infrastructure:
   support.infinitecampus.com
5. Preserve: Export IC audit logs for the incident time window
```

**Scenario D: Lost/Stolen Staff Windows Device**
```
1. Intune → Devices → [Device Name] → Remote Lock immediately
2. If confirmed stolen (not just misplaced):
   Intune → Devices → [Device Name] → Wipe (after BitLocker key recovery)
3. Retrieve BitLocker recovery key:
   Entra ID → Devices → [Device] → BitLocker keys
4. Entra ID → Users → [Staff] → Revoke sessions
5. Assess: Was BitLocker enabled? (Check Intune compliance report)
   If NO → treat as confirmed data exposure
   If YES → data encrypted, lower risk but still document
6. Defender for Endpoint → Device timeline → last known activity
```

---

### Phase 3: ASSESS

Determine the actual FERPA impact. This is where you decide how serious it is.

**FERPA Impact Assessment Questions**
```
1. WHAT data was involved?
   □ Directory information only (lower risk if directory policy published)
   □ Grades, assessments, attendance (medium-high)
   □ IEP / 504 / special education records (critical — extra protections)
   □ Disciplinary records (high)
   □ Financial/lunch eligibility data (high)
   □ Health records tied to enrollment (may trigger HIPAA too)

2. WHO accessed it?
   □ Another district staff member (internal — likely not a FERPA violation)
   □ A parent (their own child's data — not a violation)
   □ A parent (another child's data — violation)
   □ A third-party vendor (check if covered by DSAA/FERPA exception)
   □ Unknown external party (treat as confirmed violation)
   □ Malicious actor (confirmed violation + security breach)

3. HOW MANY students affected?
   □ 1-5 students (targeted, lower scale)
   □ 6-50 students (moderate — class or grade level)
   □ 50+ students (significant — district-wide response likely needed)

4. HOW LONG was it exposed?
   □ Minutes to hours (lower risk of actual access)
   □ Days to weeks (moderate — assume accessed)
   □ Months (high — assume accessed and potentially used)

5. IS there evidence of actual access by unauthorized party?
   □ Drive audit shows external download → confirmed access
   □ IC audit shows external login → confirmed access
   □ No evidence of access → potential violation, not confirmed
```

**Severity Classification**
```
SEV 1 — CRITICAL
  Special education / IEP records exposed externally
  SIS credentials compromised
  50+ students affected
  Evidence of malicious access
  → Escalate to superintendent within 1 hour
  → Engage legal counsel same day

SEV 2 — HIGH
  Grades/assessments for any number of students exposed externally
  Staff device lost without BitLocker confirmation
  Staff account compromised with SIS access
  → Escalate to superintendent within 4 hours

SEV 3 — MEDIUM
  Small number of students (1-10), directory-level data only
  Internal misdisclosure (wrong staff member)
  No evidence of external access
  → Document and notify principal within 24 hours
  → Parental notification at superintendent discretion

SEV 4 — LOW
  Accidental classroom projector display
  Internal viewing of another student's non-sensitive record
  Immediately self-corrected
  → Document internally, no external notification typically required
```

---

### Phase 4: NOTIFY

FERPA notification is not optional once a violation is confirmed.

**Internal Notification Chain (IT-owned response)**
```
Step 1: Notify your direct supervisor / Technology Director
  Immediately upon classification as SEV 1 or SEV 2

Step 2: Notify Superintendent
  SEV 1: Within 1 hour
  SEV 2: Within 4 hours
  SEV 3: Within 24 hours
  Provide: What happened, what data, how many students, what's been contained

Step 3: Notify Building Principal(s)
  For affected students' schools
  They will need to communicate with families if parental notification required

Step 4: Engage Legal Counsel
  SEV 1 always
  SEV 2 if external party involved
  They advise on state-specific notification requirements
```

**Parental Notification**
```
FERPA does not set a specific timeline for parental notification,
but best practice and many state laws require prompt notification.

Notification should include:
  □ What education records were involved
  □ Who may have accessed them
  □ When the incident occurred
  □ What the district has done to contain it
  □ What steps parents/students can take
  □ District contact for questions

DO NOT include in notification:
  □ Names of other affected students
  □ Technical details that could aid further exploitation
  □ Speculation about intent or cause
```

**U.S. Department of Education**
```
FERPA does not require reporting individual incidents to ED,
BUT if a pattern of violations is found during a complaint investigation,
the district risks losing federal funding.
Maintain thorough documentation in case of future ED audit or complaint.
```

---

### Phase 5: DOCUMENT

Documentation is your protection. Every FERPA incident must be logged.

**Incident Record — Required Fields**
```
Incident ID: [FERPA-YYYY-###]
Date/Time Detected:
Date/Time Contained:
Reported By:
Incident Summary:

Data Involved:
  - System(s): [ ] Infinite Campus [ ] Google Workspace [ ] M365/SharePoint
  - Data type(s):
  - Number of students affected:
  - Student names/IDs: (store securely, not in shared doc)

Exposure Details:
  - How exposed:
  - To whom:
  - Duration of exposure:
  - Evidence of actual access: Yes / No / Unknown

Severity: SEV 1 / 2 / 3 / 4

Containment Actions Taken:
  (list each action with timestamp)

Notifications Made:
  - Supervisor notified: [Date/Time]
  - Superintendent notified: [Date/Time]
  - Principal(s) notified: [Date/Time]
  - Legal counsel engaged: [Date/Time]
  - Families notified: [Date/Time / Method]

Root Cause:
  [ ] Misconfigured sharing settings
  [ ] Compromised staff account
  [ ] Lost/stolen device
  [ ] Accidental misdisclosure
  [ ] Vendor/third-party error
  [ ] Malicious insider
  [ ] Other:

Remediation Steps Completed:

Lessons Learned / Policy Changes Needed:

Incident Closed: [Date]
Closed By:
```

**Where to Store Incident Records**
```
  □ NOT in a shared Google Drive or SharePoint accessible to general staff
  □ Recommended: SharePoint site with IT + Administration access only
  □ Retain for minimum 3 years (align with FERPA record retention)
  □ Store securely — incident records themselves contain student PII
```

---

### Phase 6: RECOVER & IMPROVE

**Immediate Recovery Actions**
```
  □ Confirm all unauthorized access paths are closed
  □ Verify affected accounts have new credentials + MFA re-registered
  □ Confirm affected data systems are back to normal operation
  □ Brief affected staff on what happened (without shaming)
  □ Update Infinite Campus user permissions if over-provisioned
```

**Post-Incident Improvements**
```
Common root causes and fixes:

Misconfigured Google Drive sharing →
  Admin Console: Enforce sharing restrictions by OU
  Add Sentinel alert: external share of files with student name patterns

Staff account compromised →
  Entra ID: Enforce phishing-resistant MFA (FIDO2 / Authenticator app)
  CyberNut: Targeted phishing training for affected staff

Lost device, no BitLocker →
  Intune: Mark BitLocker as required in compliance policy
  Block M365 access for non-compliant devices via Conditional Access

Infinite Campus over-provisioning →
  Conduct quarterly IC access review
  Remove role permissions not needed for job function

SharePoint site misconfigured →
  SharePoint Admin: Enable default block on external sharing
  Purview DLP: Enable policy for student data patterns
```

---

## Quick Reference — FERPA Incident Decision Tree

```
Potential incident reported
         │
         ▼
Does it involve education records (student PII)?
    │                    │
   YES                   NO → Not a FERPA incident
    │                         Log as general security event
    ▼
Was it accessed/disclosed to an unauthorized party?
    │                    │
   YES               UNSURE → Investigate further (Phase 1-2)
    │
    ▼
Classify severity (Phase 3)
    │
    ▼
Contain immediately (Phase 2)
    │
    ▼
Notify per severity level (Phase 4)
    │
    ▼
Document everything (Phase 5)
    │
    ▼
Recover + Improve (Phase 6)
```

---

## Tools & Resources

| Tool | Purpose | Access |
|---|---|---|
| Google Admin Console | Drive audit logs, sharing review | admin.google.com |
| Microsoft Purview | DLP alerts, content search, compliance | compliance.microsoft.com |
| Microsoft Sentinel | SIEM alerts, unified incident log | portal.azure.com |
| Defender XDR | Endpoint + email incident data | security.microsoft.com |
| Microsoft Intune | Device compliance, remote wipe | intune.microsoft.com |
| Infinite Campus | SIS audit logs, user access review | Your IC tenant |
| Entra ID | Session revocation, account disable | entra.microsoft.com |

---

## References

- [FERPA — 20 U.S.C. § 1232g](https://studentprivacy.ed.gov/ferpa)
- [Student Privacy Policy Office — Incident Response Guide](https://studentprivacy.ed.gov)
- [NIST SP 800-61 Rev 2 — Computer Security Incident Handling](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [CIS Control 17 — Incident Response Management](https://www.cisecurity.org/controls/v8)
- [Microsoft Purview DLP Documentation](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp)
- [Google Workspace Admin — Drive Audit](https://support.google.com/a/answer/4579696)
- [Infinite Campus Security Documentation](https://kb.infinitecampus.com)
