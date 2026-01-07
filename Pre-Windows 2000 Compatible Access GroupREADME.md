# Pre-Windows 2000 Compatible Access Group

## Overview
A built-in Active Directory security principal introduced in Windows 2000 to maintain backward compatibility with Windows NT systems. Despite being 25 years old, this configuration remains prevalent in modern AD environments and presents significant security risks when misconfigured.

---
## Historical Context
Why It Exists
When Microsoft transitioned from `Windows NT 4.0 → Windows 2000 Active Directory`:
- Old model: Flat directory structure
- New model: Hierarchical OUs, domain trees, forests
- Problem: Legacy systems couldn't handle granular AD permissions
- Solution: Pre-Windows 2000 Compatible Access group
This group provides `READ access to all user and group objects at the object` level (not attribute level), allowing older applications to function without breaking.
<img width="391" height="446" alt="image" src="https://github.com/user-attachments/assets/4431c75f-a3fa-4063-825f-1298357fe6d0" />

----
## 🔍 What It Does
Default Membership 
```
Pre-Windows 2000 Compatible Access Group
└── Authenticated Users (default in ALL AD versions, including Server 2022/2025)
```
## Permissions Granted
- Read access to all users and groups in the domain
- Access to most object attributes (description, department, group membership, etc.)
- Inherited down the entire OU hierarchy
- Applies to: Descendant User objects, Group objects, InetOrgPerson objects

## ADSI Edit View
```
Special Permissions:
├── Read all properties (User objects)
├── Read all properties (Group objects)
└── Inherited to all descendant objects
```
<img width="500" height="513" alt="image" src="https://github.com/user-attachments/assets/633c1091-5967-49a3-bdcd-91a43bfb7d7c" />
<img width="500" height="586" alt="image" src="https://github.com/user-attachments/assets/f844d313-4c17-41ad-85c8-348dbbf4af75" />

---
## ⚠️ Security Risk Levels
Risk Level 1: Default Configuration (Low-Medium Risk)

Membership: Authenticated Users only
```
Impact:
✅ Any domain user can enumerate all users/groups
✅ Enables reconnaissance for password spraying
✅ Aids in attack path planning
⚠️ Requires valid credentials (authenticated access)
```
## Attack Scenario:
```
# Attacker compromises ANY domain user account
# Can now enumerate entire domain
bloodhound-python -u user@domain.com -p password -d domain.com -c all
```

---

### Risk Level 2: "Everyone" Group Added (High Risk)
**Membership:** Authenticated Users + **Everyone**
```
Impact:
⚠️ "Everyone" includes unauthenticated principals in some configurations
⚠️ Broadens attack surface beyond just domain users
⚠️ Can enable unauthenticated enumeration when combined with other misconfigurations
```

**When This Happens:**
- Legacy Windows Server 2000/2003 deployments
- Admin selected "Permissions compatible with pre-Windows 2000 servers" during DCPROMO
- Setting persisted through in-place upgrades

---

### Risk Level 3: "Anonymous Logon" Added (CRITICAL Risk) 🚨
<img width="389" height="442" alt="image" src="https://github.com/user-attachments/assets/f950db0e-6b56-4dab-a449-a38418833dda" />

**Membership:** Authenticated Users + Everyone + **Anonymous Logon**
```
CRITICAL IMPACT:
🔴 Complete unauthenticated enumeration of entire AD
🔴 No credentials required whatsoever
🔴 Attacker can read all user/group objects from the network
🔴 Enables SMB null sessions and LDAP anonymous binds
🔴 Your AD becomes a public directory
```
## Attack Scenario:
```
# From completely unauthenticated position:
netexec smb <DC-IP> --users          # Get all users
netexec smb <DC-IP> --pass-pol       # Get password policy
ldapsearch -H ldap://<DC-IP> -x -b "dc=domain,dc=com"  # Dump entire AD
```

---

## 🎯 Membership Comparison

| Member | Auth Required? | Risk Level | Common? |
|--------|---------------|------------|---------|
| Authenticated Users | ✅ Yes | Low-Medium | ✅ Default (always present) |
| Everyone | ⚠️ Sometimes | High | Medium (legacy holdover) |
| Anonymous Logon | ❌ No | CRITICAL | Low (but still found) |

---

## 🕰️ How This Persists in Modern Environments

### Windows Server 2000/2003 Era
<img width="499" height="378" alt="image" src="https://github.com/user-attachments/assets/4cd7dd37-c504-48ce-a2d7-b20359292bec" />

During Active Directory installation, admins were prompted:
```
┌─────────────────────────────────────────────────────────┐
│ Active Directory Installation Wizard                    │
├─────────────────────────────────────────────────────────┤
│ Permissions                                             │
│                                                         │
│ Select default permissions for user and group objects:  │
│                                                         │
│ ○ Permissions compatible with pre-Windows 2000 servers  │
│   (adds Everyone + Anonymous Logon)                     │
│                                                         │
│ ○ Permissions compatible with Windows 2000 servers      │
│   (Authenticated Users only - MORE SECURE)              │
└─────────────────────────────────────────────────────────┘
```

Many admins chose the first option to **avoid compatibility issues**, inadvertently creating security holes.
<img width="500" height="368" alt="image" src="https://github.com/user-attachments/assets/3dfdaa71-029e-4a4e-862b-2b8e9c7897d9" />

### Windows Server 2008+
- Admins are **no longer prompted** during DCPROMO
- Everyone/Anonymous Logon **not added by default**
- **BUT:** Settings persist through in-place DC upgrades
- Raising domain functional level **does NOT** remove these members

### Why It's Still Everywhere in 2025
```
Windows Server 2000 (Everyone + Anonymous Logon added)
         ↓ In-place upgrade
Windows Server 2003 (settings preserved)
         ↓ In-place upgrade
Windows Server 2008 (settings preserved)
         ↓ In-place upgrade
Windows Server 2012 (settings preserved)
         ↓ In-place upgrade
Windows Server 2019 (settings preserved)
         ↓ In-place upgrade
Windows Server 2022 (STILL VULNERABLE!)
```

## 🛡️ Detection & Remediation
Check Current Membership
```
# PowerShell
Get-ADGroupMember "Pre-Windows 2000 Compatible Access" | Select Name

# Expected (secure):
# - Authenticated Users

# Red flags:
# - Everyone
# - Anonymous Logon
```
## Verify from ADSI Edit
1. Open `dsa.msc` (Active Directory Users and Computers)
2. Navigate to Builtin container
3. Right-click Pre-Windows 2000 Compatible Access → Properties
4. Check Members tab

------
## Remediation Steps
Remove Dangerous Members
```
# Remove Everyone group
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" `
                     -Members "Everyone" -Confirm:$false

# Remove Anonymous Logon
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" `
                     -Members "NT AUTHORITY\ANONYMOUS LOGON" -Confirm:$false
```

#### Verify No Legacy GPO Settings
Check **Default Domain Controllers Policy**:
```
Computer Configuration
└── Windows Settings
    └── Security Settings
        └── Local Policies
            └── Security Options
                └── "Network access: Let Everyone permissions apply to anonymous users"
                    → Should be: DISABLED
```


## Additional Hardening (Optional)
If your environment doesn't need backward compatibility:
# Remove Authenticated Users (breaks some legacy apps)
# TEST THOROUGHLY before doing this!
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" `
                     -Members "Authenticated Users" -Confirm:$false
```

⚠️ **Warning:** Removing Authenticated Users may break:
- Legacy monitoring tools
- Older applications that query AD
- Third-party identity management solutions

---

## 🔗 Related Attack Vectors

When "Everyone" or "Anonymous Logon" are members, these attacks become possible:

| Attack | Requires This Group? | Document Reference |
|--------|---------------------|-------------------|
| SMB Null Session | ✅ Yes (Everyone) | Unauthenticated Recon doc |
| LDAP Anonymous Bind | ⚠️ Can contribute | Unauthenticated Recon doc |
| RID Brute Forcing | ✅ Yes (Anonymous Logon) | Unauthenticated Recon doc |
| Authenticated Enumeration | ✅ Default behavior | BloodHound, PowerView |

---

## 📊 Decision Matrix

┌─────────────────────────────────────────────────────────────────┐
│ Should I remove members from this group?                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Anonymous Logon present?                                        │
│ └─→ YES → 🔴 REMOVE IMMEDIATELY                                │
│                                                                 │
│ Everyone group present?                                         │
│ └─→ YES → 🟠 REMOVE (unless specific legacy need)               │
│                                                                 │
│ Only Authenticated Users?                                       │
│ └─→ 🟢 Acceptable default (but reduces security posture)        │
│                                                                 │
│ No members at all?                                              │
│ └─→ 🟢 Most secure (may break legacy apps)                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎓 Key Takeaways

1. **Default ≠ Secure**: Authenticated Users membership is default but still aids reconnaissance
2. **Legacy Debt**: Settings from 25 years ago persist through upgrades indefinitely
3. **Critical Misconfiguration**: Anonymous Logon membership = complete unauthenticated access
4. **Check Every DC**: Verify membership on all domain controllers in the forest
5. **Test Before Removing**: Even removing "Everyone" can break legacy applications

---

## 📚 Technical Details

### Group Properties
```
Name: Pre-Windows 2000 Compatible Access
Type: Built-in security group (Local Domain)
Scope: Domain Local
SID: S-1-5-32-554
Location: CN=Builtin,DC=domain,DC=com
```

### Default Description
> "A backward compatibility group which allows read access on all users and groups in the domain"

### Permissions Structure (ADSI Edit)
```
Advanced Security Settings for Domain Object
├── Principal: Pre-Windows 2000 Compatible Access
├── Type: Allow
├── Applies to: Descendant User objects
├── Applies to: Descendant Group objects
├── Applies to: Descendant InetOrgPerson objects
└── Permissions: Read all properties (inherited)
```
## 🔍 Quick Audit Commands
```
# Check membership
Get-ADGroupMember "Pre-Windows 2000 Compatible Access" | Select Name

# Check if Everyone is a member (dangerous)
Get-ADGroupMember "Pre-Windows 2000 Compatible Access" | 
    Where-Object {$_.Name -eq "Everyone"}

# Export full membership for documentation
Get-ADGroupMember "Pre-Windows 2000 Compatible Access" | 
    Export-Csv "PreWin2000Access_Audit.csv" -NoTypeInformation
```

## 📖 Additional Resources
- https://learn.microsoft.com/
- https://adsecurity.org/
- https://www.pingcastle.com/
-----


## NOTES: Pre-Windows 2000 Compatible Access Group - Simple Explanation

## What Is It?
A built-in Active Directory group that was created 25 years ago to help old Windows NT systems work with the new Active Directory in Windows 2000.

## The Problem
By default, this group gives READ access to view all users and groups in the domain. This means:
- Any authenticated user can see the entire user list
- Attackers can use this for reconnaissance and password spraying attacks
- It's a 25-year-old legacy feature that still exists in modern AD environments

## The REAL Danger
While having "Authenticated Users" in this group is the default (and somewhat manageable), the group can also contain:
1. Everyone - Includes all users, even unauthenticated ones (less common but still seen)
2. Anonymous Logon - THIS IS THE MOST DANGEROUS ⚠️

## Why "Anonymous Logon" is the Worst
If Anonymous Logon is a member of this group, attackers can:
- Enumerate (list) ALL users and groups
- Read user attributes and descriptions
- Gather information for attacks
- WITHOUT EVEN LOGGING IN (completely unauthenticated)
This essentially makes your entire Active Directory a public phonebook that anyone on the network can read.

----
What is the most dangerous group member to include in the Pre-Windows 2000 Compatible Access group?
Answer: `Anonymous Logon`
