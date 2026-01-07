# Unauthenticated Recon & Enumeration Weaknesses

## 🎯 Overview
Three legacy Active Directory misconfigurations allow attackers to enumerate domain information without authentication. Despite being 25+ years old, these vulnerabilities remain common in 2025 due to in-place domain controller upgrades preserving Windows 2000 era settings.

## ⚠️ The Risk
What Attackers Can Obtain (No Authentication Required)
- Complete list of all domain users
- Domain password policy details
- User/computer attributes (descriptions may contain passwords)
- Group memberships

## Attack Chain
```
Unauthenticated Enumeration → Password Spraying → Initial Access
```

## 🔓 Three Attack Vectors
1. SMB Null Session

What it is: Connects to SMB with empty credentials to query Active Directory
## Demo Attack:
```
# Enumerate all users
netexec smb 192.168.195.138 --users

# Get password policy
netexec smb 192.168.195.138 --pass-pol
```

**Root Cause:**
- "Everyone" group in **Pre-Windows 2000 Compatible Access** group
- GPO: "Let Everyone permissions apply to anonymous users" = Enabled

**Fix:**
1. Remove "Everyone" from Pre-Windows 2000 Compatible Access group
2. Set Group Policy:
```
   Computer Configuration → Windows Settings → Security Settings 
   → Local Policies → Security Options
   → "Network access: Let Everyone permissions apply to anonymous users" = DISABLED
```
3. Run `gpupdate /force`

----
<img width="500" height="314" alt="image" src="https://github.com/user-attachments/assets/6ab02dba-ec8b-4ab7-8f4d-965ed7891a46" />

Disabling anonymous SID/name translation in Group Policy

---
## 2. LDAP Anonymous Bind
What it is: Queries Active Directory via LDAP without credentials
```
ldapsearch -H ldap://192.168.195.147 -x -b "dc=domain,dc=com"
```

Root Cause:
- `dsHeuristics` attribute = `0000002`
- ANONYMOUS LOGON has read permissions on CN=Users

Manual Fix Steps:

<img width="500" height="564" alt="image" src="https://github.com/user-attachments/assets/304d17f6-fa81-4441-9f59-9ec476af8a3f" />

Connecting to Configuration naming context in ADSI Edit

----
1. Open `adsiedit.msc`
2. Connect to Configuration naming context
<img width="671" height="546" alt="image" src="https://github.com/user-attachments/assets/0a78879d-b217-47c4-8b9a-a9a5f3745228" />

Navigate to CN=Directory Service under CN=Windows NT
3. Navigate to: `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration`

<img width="391" height="445" alt="image" src="https://github.com/user-attachments/assets/d79f6e20-f6ae-4033-89b1-57b9f284a7ac" />

The dsHeuristics attribute set to 0000002 enables anonymous binds

4. Right-click `CN=Directory Service` → Properties

5.Clear the dsHeuristics attribute value

----
<img width="385" height="441" alt="image" src="https://github.com/user-attachments/assets/90db0b23-e9d7-45c2-8793-08c1d724f222" />

6. Remove ANONYMOUS LOGON read permissions from CN=Users

----
## PowerShell Fix (Automated):
```
# Clear dsHeuristics attribute
$Dcname = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
$Adsi = 'LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,' + $Dcname
$AnonADSI = [ADSI]$Adsi
$AnonADSI.Properties["dSHeuristics"].Clear()
$AnonADSI.SetInfo()

# Remove ANONYMOUS LOGON read access from CN=Users
$ADSI = [ADSI]('LDAP://CN=Users,' + $Dcname)
$Anon = New-Object System.Security.Principal.NTAccount("ANONYMOUS LOGON")
$SID = $Anon.Translate([System.Security.Principal.SecurityIdentifier])
$adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericRead"
$type = [System.Security.AccessControl.AccessControlType] "Allow"
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID,$adRights,$type,$inheritanceType
$ADSI.PSBase.ObjectSecurity.RemoveAccessRule($ace) | Out-Null
$ADSI.PSBase.CommitChanges()
```
## RID Brute Forcing
What it is: Enumerates users/groups by guessing sequential RID values
Demo Attack:
```
netexec smb 192.168.195.138 --rid-brute
```

**How it Works:**
```
S-1-5-21-<domain-ID>-500  → Administrator
S-1-5-21-<domain-ID>-501  → Guest  
S-1-5-21-<domain-ID>-1000 → First user
S-1-5-21-<domain-ID>-1001 → Second user
...
```

**Root Cause:**
- GPO: "Network access: Allow anonymous SID/name translation" = Enabled

**Fix:**
```
Default Domain Controllers Policy:
Computer Configuration → Security Settings → Local Policies → Security Options
→ "Network access: Allow anonymous SID/name translation" = DISABLED
```

**Alternative (Registry):**
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous = 1 or 2
```

---

## 📊 Vulnerability History

| Windows Version | Default Vulnerable? | Why? |
|----------------|-------------------|------|
| NT 4.0 | ✅ Yes | Legacy default |
| Server 2000/2003 | ⚠️ If admin selected "Pre-Windows 2000 compatibility" during DCPROMO | Admin choice during installation |
| Server 2008+ | ❌ No | Not enabled by default |
| **Upgraded DCs (2000→2003→2008→2019→2022)** | ✅ **YES** | **Settings persist through upgrades** |

### Why Still Vulnerable in 2025?
```
Windows Server 2000 (Misconfigured)
         ↓ In-place upgrade
Windows Server 2008 (Settings preserved)
         ↓ In-place upgrade  
Windows Server 2019 (Settings preserved)
         ↓ In-place upgrade
Windows Server 2022 (STILL VULNERABLE!)
```
Key Point: Raising domain functional level does NOT remove these settings.

----
## 🛡️ Detection & Remediation
Quick Audit Commands
```
# Check for SMB null session vulnerability
netexec smb <DC-IP> --users

# Check for LDAP anonymous bind
ldapsearch -H ldap://<DC-IP> -x -b "dc=domain,dc=com"

# Check for RID brute forcing
netexec smb <DC-IP> --rid-brute

# Check Pre-Windows 2000 Compatible Access membership
Get-ADGroupMember "Pre-Windows 2000 Compatible Access" | Select Name
```
<img width="576" height="235" alt="image" src="https://github.com/user-attachments/assets/9292aa64-f68f-4b62-a73e-3430a795f2dd" />

⚠️ Disclaimer
This documentation is for educational and defensive security purposes only. Always obtain proper authorization before testing on production system

----
# NOTES:
## Unauthenticated Recon & Enumeration - Simple Explanation
The Problem

Attackers can gather critical information about Active Directory `WITHOUT logging in`. This includes:
- complete list of all users
- Password policy details
- User attributes (sometimes containing passwords!)

With this info, they can perform `password spraying attacks` (trying common passwords against many accounts).

---
# Three Attack Methods
## 1. SMB Null Session
- Connects to SMB without credentials
- Gets full user list + password policy
- Works if "Everyone" group is in Pre-Windows 2000 Compatible Access

Fix:
- Remove "Everyone" from Pre-Windows 2000 Compatible Access group
- Set GPO: "Let Everyone permissions apply to anonymous users" = Disabled

## 2. LDAP Anonymous Bind ⚠️ (Your Question!)

Queries Active Directory via LDAP without authentication
Gets users, groups, computers, password policy
Works if `dsHeuristics` attribute = `0000002`

fix:
- Clear the `dsHeuristics` attribute (remove the value entirely)
- Remove ANONYMOUS LOGON read permissions from CN=Users


## 2. RID Brute Forcing
- Guesses user/group names by trying sequential RID numbers (500, 501, 1000, 1001...)
- Works if "Allow anonymous SID/name translation" is enabled

Fix:
- Set GPO: "Network access: Allow anonymous SID/name translation" = `Disabled`

What attribute must be cleared to prevent LDAP anonymous binds?
Answer: `dsHeuristics`

## Key Takeaway
All three attacks are legacy misconfigurations from Windows 2000 era that still exist today because:
- Domain controllers were upgraded in place over 20+ years
- Settings were "pulled along" and never cleaned up
- Even modern domains sometimes enable these for "compatibility"

Solution: Clean up these legacy settings unless there's a clear business need!
