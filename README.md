<img width="450" height="450" alt="image" src="https://github.com/user-attachments/assets/fc6e9dbc-bbad-4e86-9531-cd51e7e44c8f" />

# Active Directory Hardening – Recon & Initial Access

## Overview
This project documents common Active Directory weaknesses that allow **unauthenticated reconnaissance and initial access**.  
The focus is on **identity risk, business impact, and remediation**, aligned with IAM and Active Directory Administrator responsibilities.

All testing was performed in a **simulated lab environment**.

---

## Scenario Summary
An enterprise environment underwent its first internal penetration test. Several **legacy Active Directory configurations** allowed unauthenticated enumeration of users and password policies, which were later leveraged for password spraying and initial access.

---

## Key Findings
- Unauthenticated Active Directory enumeration
- SMB null session exposure
- LDAP anonymous bind enabled
- RID brute-force enumeration
- Weak password policy visibility

---

## IAM / AD Impact
- Enables password spraying attacks
- Increases identity attack surface
- Violates least privilege and Zero Trust principles
- Common in environments upgraded from older Windows Server versions

---

## Remediation Summary
- Removed legacy Pre-Windows 2000 access permissions
- Disabled anonymous LDAP binds
- Hardened Group Policy security options
- Restricted anonymous SID/name translation

---

## Skills Demonstrated
- Active Directory Security Hardening
- IAM Risk Analysis
- Group Policy Configuration
- LDAP & Kerberos Fundamentals
- Defensive Identity Security

📄 Detailed background and scenario available in `/docs`.
